#include "secure/http/api_error.hpp"
#include "secure/http/cors_policy.hpp"
#include "secure/http/http_types.hpp"
#include "secure/http/request_id.hpp"
#include "secure/http/request_validation.hpp"
#include "secure/http/router.hpp"
#include "secure/net/trusted_proxy.hpp"

#include <cstdlib>
#include <exception>
#include <iostream>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

#include <boost/beast/http.hpp>

namespace {

void require(bool condition, std::string_view message) {
    if (!condition) {
        throw std::runtime_error(std::string(message));
    }
}

secure::HttpResponse ok_response(
    const secure::HttpRequest&
) {
    secure::HttpResponse response;
    response.result(boost::beast::http::status::ok);
    response.body() = "{}";
    return response;
}

void test_query_corpus() {
    const std::vector<std::string> corpus{
        "/?a=1",
        "/?a=%ZZ",
        "/?a=%",
        "/?a=%00",
        "/?a=hello+world",
        "/?a=1&a=2",
        "/?=empty-key",
        "/?a=",
        "/?a=%2Fusers%2F1",
        std::string("/?a=x\0y", 8)
    };

    for (const std::string& target : corpus) {
        static_cast<void>(
            secure::query_parameter(target, "a")
        );
    }

    require(
        secure::query_parameter("/?a=hello+world", "a") ==
            std::optional<std::string>("hello world"),
        "query plus decoding"
    );
}

void test_router_corpus() {
    secure::Router router;
    router.get("/health", ok_response);
    router.get("/users/{id}", ok_response);

    const std::vector<std::string> targets{
        "/health",
        "/users/1",
        "/users/%31",
        "/users/%",
        "/users/%ZZ",
        "/users/",
        "/users//",
        "/?query=%00",
        "not-absolute",
        std::string("/users/x\0y", 10)
    };

    for (const std::string& target : targets) {
        secure::HttpRequest request;
        request.version(11);
        request.method(boost::beast::http::verb::get);
        request.target(target);
        static_cast<void>(router.dispatch(request));
    }
}

void test_proxy_corpus() {
    const secure::TrustedProxyResolver resolver(
        {"127.0.0.1/32", "10.0.0.0/8", "::1/128"},
        4096
    );

    secure::HttpRequest valid;
    valid.set(
        "X-Forwarded-For",
        "198.51.100.7, 10.1.2.3"
    );
    valid.set("X-Forwarded-Proto", "https");

    const auto resolved = resolver.resolve(
        "127.0.0.1",
        valid,
        false
    );

    require(
        resolved.client_ip == "198.51.100.7",
        "trusted proxy client address"
    );
    require(
        resolved.secure_transport,
        "trusted proxy HTTPS scheme"
    );

    const std::vector<std::string> malformed{
        "for=unknown",
        "for=\"[2001:db8::1\"",
        "for=198.51.100.1;proto=ftp",
        "for=198.51.100.1,",
        "for=\"unterminated",
        "for=_hidden"
    };

    for (const std::string& value : malformed) {
        secure::HttpRequest request;
        request.set("Forwarded", value);

        bool rejected = false;
        try {
            static_cast<void>(
                resolver.resolve(
                    "127.0.0.1",
                    request,
                    false
                )
            );
        } catch (const secure::ProxyHeaderError&) {
            rejected = true;
        }
        require(rejected, "malformed proxy header rejection");
    }
}

void test_cors_corpus() {
    const secure::CorsPolicy policy(
        {
            "https://admin.example.com",
            "https://app.example.com"
        },
        true,
        600
    );

    require(
        policy.allows("https://app.example.com"),
        "allowed CORS origin"
    );
    require(
        !policy.allows("https://evil.example.com"),
        "denied CORS origin"
    );

    const std::vector<std::string> invalid{
        "",
        "ftp://example.com",
        "https://example.com/path",
        "https://user@example.com",
        "https://example.com?x=1",
        "https://example.com#fragment"
    };

    for (const std::string& origin : invalid) {
        bool rejected = false;
        try {
            const secure::CorsPolicy candidate(
                {origin},
                false,
                600
            );
            static_cast<void>(candidate);
        } catch (const std::invalid_argument&) {
            rejected = true;
        }
        require(rejected, "invalid CORS origin rejection");
    }
}

void test_request_id_corpus() {
    secure::HttpRequest valid;
    valid.set("X-Request-ID", "client.request-123");
    require(
        secure::resolve_request_id(valid) ==
            "client.request-123",
        "valid request ID preservation"
    );

    const std::vector<std::string> invalid{
        "",
        "contains space",
        "contains/slash",
        std::string(65, 'a'),
        "unicode-\xC3\xA9"
    };

    for (const std::string& value : invalid) {
        secure::HttpRequest request;
        request.set("X-Request-ID", value);
        const std::string resolved =
            secure::resolve_request_id(request);
        require(
            !resolved.empty() && resolved != value,
            "invalid request ID replacement"
        );
    }
}

void test_json_corpus() {
    const std::vector<std::string> invalid{
        "",
        "null",
        "[]",
        "{",
        "{\"x\":}",
        "{\"x\":1} trailing",
        std::string("{\"x\":\"a\0b\"}", 11)
    };

    for (const std::string& body : invalid) {
        secure::HttpRequest request;
        request.set(
            boost::beast::http::field::content_type,
            "application/json"
        );
        request.body() = body;

        try {
            static_cast<void>(
                secure::parse_json_object(request)
            );
        } catch (const secure::ApiException&) {
        }
    }

    secure::HttpRequest valid;
    valid.set(
        boost::beast::http::field::content_type,
        "application/json; charset=utf-8"
    );
    valid.body() = "{\"enabled\":true,\"name\":\"alice\"}";

    const secure::Json object =
        secure::parse_json_object(valid);
    require(object.is_object(), "valid JSON object");
}

}  // namespace

int main() {
    try {
        test_query_corpus();
        test_router_corpus();
        test_proxy_corpus();
        test_cors_corpus();
        test_request_id_corpus();
        test_json_corpus();
    } catch (const std::exception& error) {
        std::cerr
            << "Security parser corpus test failed: "
            << error.what()
            << '\n';
        return EXIT_FAILURE;
    }

    std::cout << "Security parser corpus tests passed.\n";
    return EXIT_SUCCESS;
}
