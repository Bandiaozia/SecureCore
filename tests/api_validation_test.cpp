#include "secure/http/api_error.hpp"
#include "secure/http/json_utils.hpp"
#include "secure/http/request_id.hpp"
#include "secure/http/request_validation.hpp"
#include "secure/http/router.hpp"

#include <cstdlib>
#include <iostream>
#include <limits>
#include <stdexcept>
#include <string>

#include <boost/beast/http.hpp>

namespace {

namespace http = boost::beast::http;

void require(
    bool condition,
    const char* message
) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

secure::HttpRequest json_request(
    std::string body
) {
    secure::HttpRequest request{
        http::verb::post,
        "/test",
        11
    };

    request.set(
        http::field::content_type,
        "application/json; charset=utf-8"
    );

    request.body() = std::move(body);
    request.prepare_payload();

    return request;
}

void test_structured_error() {
    secure::HttpResponse response =
        secure::make_validation_error(
            {
                {"username", "is required"},
                {"password", "must be a string"}
            }
        );

    secure::apply_request_id(
        response,
        "test-request-42"
    );

    const secure::Json body =
        secure::Json::parse(response.body());

    require(
        response.result() ==
            http::status::unprocessable_entity,
        "validation status"
    );

    require(
        response["X-Request-ID"] ==
            "test-request-42",
        "request id response header"
    );

    require(
        body.at("error").at("code") ==
            "validation_failed",
        "validation error code"
    );

    require(
        body.at("error").at("message") ==
            "Request validation failed.",
        "validation error message"
    );

    require(
        body.at("error").at("request_id") ==
            "test-request-42",
        "request id in error body"
    );

    require(
        body.at("error").at("details").size() == 2,
        "validation details size"
    );
}

void test_json_validation() {
    const secure::Json body =
        secure::parse_json_object(
            json_request(
                R"({"username":123})"
            )
        );

    secure::JsonObjectValidator validator(body);

    const auto username =
        validator.required_string(
            "username"
        );

    const auto email =
        validator.required_string(
            "email"
        );

    require(
        !username.has_value(),
        "wrong string type"
    );

    require(
        !email.has_value(),
        "missing string field"
    );

    try {
        validator.throw_if_invalid();
        require(false, "validation exception expected");
    } catch (const secure::ApiException& error) {
        require(
            error.status() ==
                http::status::unprocessable_entity,
            "validation exception status"
        );

        require(
            error.error().details.size() == 2,
            "aggregated validation details"
        );
    }
}

void test_request_shape_errors() {
    secure::HttpRequest unsupported{
        http::verb::post,
        "/test",
        11
    };

    unsupported.set(
        http::field::content_type,
        "text/plain"
    );

    unsupported.body() = "{}";
    unsupported.prepare_payload();

    try {
        static_cast<void>(
            secure::parse_json_object(
                unsupported
            )
        );
        require(false, "media type exception expected");
    } catch (const secure::ApiException& error) {
        require(
            error.status() ==
                http::status::unsupported_media_type,
            "unsupported media status"
        );
        require(
            error.error().code ==
                "unsupported_media_type",
            "unsupported media code"
        );
    }

    try {
        static_cast<void>(
            secure::parse_json_object(
                json_request("{")
            )
        );
        require(false, "JSON parse exception expected");
    } catch (const secure::ApiException& error) {
        require(
            error.status() ==
                http::status::bad_request,
            "invalid JSON status"
        );
        require(
            error.error().code ==
                "invalid_json",
            "invalid JSON code"
        );
    }
}

void test_integer_validation() {
    secure::RouteParameters parameters{
        {"id", "42"}
    };

    require(
        secure::require_path_integer(
            parameters,
            "id"
        ) == 42,
        "path integer"
    );

    secure::HttpRequest request{
        http::verb::get,
        "/users?limit=20&offset=3",
        11
    };

    require(
        secure::query_integer_or_default(
            request,
            "limit",
            50,
            1,
            100
        ) == 20,
        "query integer"
    );

    require(
        secure::query_integer_or_default(
            request,
            "missing",
            7,
            0,
            10
        ) == 7,
        "query default"
    );

    parameters["id"] = "zero";

    try {
        static_cast<void>(
            secure::require_path_integer(
                parameters,
                "id"
            )
        );
        require(false, "path validation expected");
    } catch (const secure::ApiException& error) {
        require(
            error.error().details.front().field ==
                "id",
            "path validation field"
        );
    }
}

void test_input_rules() {
    require(
        secure::valid_username_input(
            " secure_user-1 "
        ),
        "valid username"
    );

    require(
        !secure::valid_username_input("a"),
        "short username"
    );

    require(
        secure::valid_email_input(
            " User@example.com "
        ),
        "valid email"
    );

    require(
        !secure::valid_email_input(
            "invalid-email"
        ),
        "invalid email"
    );

    require(
        secure::valid_password_input(
            "12345678"
        ),
        "valid password length"
    );

    require(
        !secure::valid_password_input(
            "short"
        ),
        "short password"
    );
}

void test_request_id_resolution() {
    secure::HttpRequest request{
        http::verb::get,
        "/health",
        11
    };

    request.set(
        "X-Request-ID",
        "client.request-1"
    );

    require(
        secure::resolve_request_id(request) ==
            "client.request-1",
        "valid client request id"
    );

    request.set(
        "X-Request-ID",
        "not valid"
    );

    const std::string generated =
        secure::resolve_request_id(request);

    require(
        !generated.empty() &&
        generated != "not valid",
        "invalid request id replaced"
    );
}

}  // namespace

int main() {
    try {
        test_structured_error();
        test_json_validation();
        test_request_shape_errors();
        test_integer_validation();
        test_input_rules();
        test_request_id_resolution();

        std::cout
            << "API validation tests passed\n";

        return EXIT_SUCCESS;
    } catch (const std::exception& error) {
        std::cerr
            << "API validation test failed: "
            << error.what()
            << '\n';

        return EXIT_FAILURE;
    }
}
