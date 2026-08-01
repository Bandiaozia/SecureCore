#include "secure/http/cors_policy.hpp"
#include "secure/http/http_types.hpp"
#include "secure/net/trusted_proxy.hpp"

#include <cstdlib>
#include <iostream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

#include <boost/beast/http.hpp>

namespace {

namespace http = boost::beast::http;

void require(
    bool condition,
    std::string_view message
) {
    if (!condition) {
        throw std::runtime_error(
            std::string(message)
        );
    }
}

template <typename Function>
void require_proxy_error(
    Function&& function,
    std::string_view expected_code
) {
    try {
        function();
    } catch (const secure::ProxyHeaderError& error) {
        require(
            error.code() == expected_code,
            "Unexpected proxy error code"
        );
        return;
    }

    throw std::runtime_error(
        "Expected ProxyHeaderError"
    );
}

template <typename Function>
void require_throws(
    Function&& function
) {
    try {
        function();
    } catch (const std::exception&) {
        return;
    }

    throw std::runtime_error(
        "Expected an exception"
    );
}

secure::HttpRequest make_request() {
    secure::HttpRequest request{
        http::verb::get,
        "/health",
        11
    };

    request.set(http::field::host, "localhost");
    return request;
}

}  // namespace

int main() {
    try {
        secure::TrustedProxyResolver resolver(
            {
                "127.0.0.1/32",
                "10.0.0.0/8",
                "2001:db8:ffff::/48"
            },
            256
        );

        require(
            resolver.is_trusted("127.0.0.1"),
            "Loopback proxy should be trusted"
        );
        require(
            resolver.is_trusted("10.20.30.40"),
            "IPv4 CIDR match failed"
        );
        require(
            resolver.is_trusted("2001:db8:ffff::42"),
            "IPv6 CIDR match failed"
        );
        require(
            !resolver.is_trusted("198.51.100.1"),
            "Public client must not be trusted"
        );

        {
            auto request = make_request();
            request.set(
                "X-Forwarded-For",
                "198.51.100.10, 10.0.0.9"
            );
            request.set(
                "X-Forwarded-Proto",
                "https"
            );

            const auto resolved = resolver.resolve(
                "127.0.0.1",
                request,
                false
            );

            require(
                resolved.client_ip == "198.51.100.10",
                "Trusted proxy chain was not stripped correctly"
            );
            require(
                resolved.secure_transport,
                "Trusted forwarded HTTPS scheme was not used"
            );
            require(
                resolved.used_forwarded_headers,
                "Forwarding use was not reported"
            );
        }

        {
            auto request = make_request();
            request.set(
                "Forwarded",
                "for=198.51.100.20;proto=https, for=10.0.0.8"
            );

            const auto resolved = resolver.resolve(
                "127.0.0.1",
                request,
                false
            );

            require(
                resolved.client_ip == "198.51.100.20",
                "RFC Forwarded chain was not resolved"
            );
            require(
                resolved.secure_transport,
                "RFC Forwarded proto was not resolved"
            );
        }

        {
            auto request = make_request();
            request.set(
                "X-Forwarded-For",
                "203.0.113.55"
            );
            request.set(
                "X-Forwarded-Proto",
                "https"
            );

            const auto resolved = resolver.resolve(
                "198.51.100.99",
                request,
                false
            );

            require(
                resolved.client_ip == "198.51.100.99",
                "Untrusted peer spoofed the client address"
            );
            require(
                !resolved.secure_transport,
                "Untrusted peer spoofed HTTPS"
            );
            require(
                !resolved.used_forwarded_headers,
                "Untrusted forwarding headers were marked as used"
            );
        }

        {
            auto request = make_request();
            request.set("X-Real-IP", "[2001:db8::5]:443");

            const auto resolved = resolver.resolve(
                "127.0.0.1",
                request,
                true
            );

            require(
                resolved.client_ip == "2001:db8::5",
                "Bracketed IPv6 X-Real-IP was not parsed"
            );
            require(
                resolved.secure_transport,
                "Direct TLS state was lost"
            );
        }

        {
            auto request = make_request();
            request.set(
                "X-Forwarded-For",
                "unknown"
            );

            require_proxy_error(
                [&] {
                    static_cast<void>(
                        resolver.resolve(
                            "127.0.0.1",
                            request,
                            false
                        )
                    );
                },
                "invalid_forwarded_header"
            );
        }

        {
            auto request = make_request();
            request.set(
                "X-Forwarded-For",
                std::string(300, '1')
            );

            require_proxy_error(
                [&] {
                    static_cast<void>(
                        resolver.resolve(
                            "127.0.0.1",
                            request,
                            false
                        )
                    );
                },
                "forwarded_header_too_large"
            );
        }

        {
            secure::CorsPolicy policy(
                {
                    "https://admin.example.com",
                    "https://app.example.com"
                },
                true,
                600
            );

            require(
                policy.allows("https://app.example.com"),
                "Exact CORS origin was not allowed"
            );
            require(
                !policy.allows("https://evil.example.com"),
                "Unknown CORS origin was allowed"
            );
            require(
                policy.allow_credentials(),
                "Credential policy was not retained"
            );
        }

        {
            secure::CorsPolicy wildcard(
                {"*"},
                false,
                60
            );

            require(
                wildcard.wildcard(),
                "Wildcard CORS policy was not detected"
            );
            require(
                wildcard.allows("https://any.example"),
                "Wildcard CORS policy denied an origin"
            );
        }

        require_throws(
            [] {
                secure::CorsPolicy invalid(
                    {"*"},
                    true,
                    600
                );
                static_cast<void>(invalid);
            }
        );

        require_throws(
            [] {
                secure::CorsPolicy invalid(
                    {"https://app.example.com/path"},
                    false,
                    600
                );
                static_cast<void>(invalid);
            }
        );

        std::cout
            << "Proxy security tests passed.\n";

        return EXIT_SUCCESS;
    } catch (const std::exception& error) {
        std::cerr
            << "Proxy security test failed: "
            << error.what()
            << '\n';

        return EXIT_FAILURE;
    }
}
