#include "secure/http/api_error.hpp"

#include "secure/http/json_utils.hpp"

#include <string>
#include <string_view>
#include <utility>

#include <boost/beast/core/string.hpp>
#include <boost/beast/http.hpp>

namespace secure {

namespace beast = boost::beast;
namespace http = beast::http;

namespace {

bool response_is_json(
    const HttpResponse& response
) {
    const beast::string_view content_type =
        response[http::field::content_type];

    if (content_type.empty()) {
        return false;
    }

    const auto separator =
        content_type.find(';');

    return beast::iequals(
        content_type.substr(0, separator),
        "application/json"
    );
}

}  // namespace

ApiException::ApiException(
    http::status status,
    ApiError error
)
    : std::runtime_error(error.message),
      status_(status),
      error_(std::move(error)) {
}

http::status ApiException::status()
    const noexcept {
    return status_;
}

const ApiError& ApiException::error()
    const noexcept {
    return error_;
}

std::string default_api_error_message(
    std::string_view code
) {
    if (code == "bad_request") {
        return "The request is invalid.";
    }
    if (code == "not_found") {
        return "The requested resource was not found.";
    }
    if (code == "method_not_allowed") {
        return "The HTTP method is not allowed for this resource.";
    }
    if (code == "unsupported_media_type") {
        return "Content-Type must be application/json.";
    }
    if (code == "empty_body") {
        return "A JSON request body is required.";
    }
    if (code == "invalid_json") {
        return "The request body is not valid JSON.";
    }
    if (code == "validation_failed") {
        return "Request validation failed.";
    }
    if (code == "payload_too_large") {
        return "The request body exceeds the configured size limit.";
    }
    if (code == "headers_too_large") {
        return "The request headers exceed the configured size limit.";
    }
    if (code == "rate_limit_exceeded") {
        return "Too many requests were sent.";
    }
    if (code == "connection_limit_reached") {
        return "The server connection limit has been reached.";
    }
    if (code == "server_busy") {
        return "The server is temporarily busy.";
    }
    if (code == "server_shutting_down") {
        return "The server is shutting down.";
    }
    if (code == "missing_access_token") {
        return "A Bearer access token is required.";
    }
    if (code == "invalid_credentials") {
        return "The login or password is invalid.";
    }
    if (code == "account_disabled") {
        return "The user account is disabled.";
    }
    if (code == "invalid_access_token") {
        return "The access token is invalid.";
    }
    if (code == "access_token_expired") {
        return "The access token has expired.";
    }
    if (code == "invalid_refresh_token") {
        return "The refresh token is invalid.";
    }
    if (code == "refresh_token_expired") {
        return "The refresh token has expired.";
    }
    if (code == "token_creation_failed") {
        return "Authentication tokens could not be created.";
    }
    if (code == "duplicate_user") {
        return "The username or email address is already in use.";
    }
    if (code == "admin_permission_required") {
        return "Administrator permission is required.";
    }
    if (code == "user_not_found") {
        return "The user was not found.";
    }
    if (code == "cannot_disable_self") {
        return "An administrator cannot disable their own account.";
    }
    if (code == "session_not_found") {
        return "The authentication session was not found.";
    }
    if (code == "invalid_current_password") {
        return "The current password is invalid.";
    }
    if (code == "same_password") {
        return "The new password must differ from the current password.";
    }
    if (code == "internal_server_error") {
        return "An internal server error occurred.";
    }

    return "The request could not be completed.";
}

HttpResponse make_api_error_response(
    http::status status,
    ApiError error
) {
    Json error_json{
        {"code", std::move(error.code)},
        {"message", std::move(error.message)}
    };

    if (!error.details.empty()) {
        Json details = Json::array();

        for (auto& detail : error.details) {
            details.push_back(
                Json{
                    {"field", std::move(detail.field)},
                    {"reason", std::move(detail.reason)}
                }
            );
        }

        error_json["details"] =
            std::move(details);
    }

    return make_json_response(
        status,
        Json{
            {"error", std::move(error_json)}
        }
    );
}

HttpResponse make_json_error(
    http::status status,
    std::string_view error_code
) {
    return make_api_error_response(
        status,
        ApiError{
            std::string(error_code),
            default_api_error_message(
                error_code
            ),
            {}
        }
    );
}

HttpResponse make_json_error(
    http::status status,
    std::string_view error_code,
    std::string_view message
) {
    return make_api_error_response(
        status,
        ApiError{
            std::string(error_code),
            std::string(message),
            {}
        }
    );
}

HttpResponse make_validation_error(
    std::vector<ApiErrorDetail> details
) {
    return make_api_error_response(
        http::status::unprocessable_entity,
        ApiError{
            "validation_failed",
            default_api_error_message(
                "validation_failed"
            ),
            std::move(details)
        }
    );
}

void attach_request_id_to_api_error(
    HttpResponse& response,
    std::string_view request_id
) {
    if (
        request_id.empty() ||
        response.body().empty() ||
        !response_is_json(response)
    ) {
        return;
    }

    try {
        Json body = Json::parse(
            response.body()
        );

        if (!body.is_object()) {
            return;
        }

        auto error = body.find("error");

        if (
            error == body.end() ||
            !error->is_object()
        ) {
            return;
        }

        (*error)["request_id"] =
            std::string(request_id);

        response.body() = body.dump();
        response.prepare_payload();
    } catch (const Json::exception&) {
        /*
         * A non-SecureCore JSON response is left untouched.
         * Request ID propagation must never replace a valid response.
         */
    }
}

}  // namespace secure
