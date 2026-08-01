#include "secure/http/middleware.hpp"

#include "secure/audit/request_audit_context.hpp"
#include "secure/http/api_error.hpp"
#include "secure/http/json_utils.hpp"
#include "secure/http/request_id.hpp"
#include "secure/http/rate_limiter.hpp"
#include "secure/log/logger.hpp"
#include "secure/observability/metrics_registry.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cctype>
#include <exception>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <boost/beast/core/string.hpp>
#include <boost/beast/http.hpp>

namespace secure {

namespace beast = boost::beast;
namespace http = beast::http;

namespace {

constexpr std::string_view allowed_methods =
    "GET, POST, PUT, PATCH, DELETE, OPTIONS";

constexpr std::string_view allowed_headers =
    "Authorization, Content-Type, X-Request-ID";

constexpr std::array<std::string_view, 6>
    allowed_method_values{
        "GET",
        "POST",
        "PUT",
        "PATCH",
        "DELETE",
        "OPTIONS"
    };

constexpr std::array<std::string_view, 3>
    allowed_header_values{
        "authorization",
        "content-type",
        "x-request-id"
    };

std::string trim_copy(
    std::string_view value
) {
    const auto first = value.find_first_not_of(
        " \t\r\n"
    );

    if (first == std::string_view::npos) {
        return {};
    }

    const auto last = value.find_last_not_of(
        " \t\r\n"
    );

    return std::string(
        value.substr(first, last - first + 1)
    );
}

std::string lowercase_copy(
    std::string_view value
) {
    std::string result(value);

    for (char& character : result) {
        character = static_cast<char>(
            std::tolower(
                static_cast<unsigned char>(character)
            )
        );
    }

    return result;
}

std::optional<std::string> request_header(
    const HttpRequest& request,
    beast::string_view name
) {
    std::optional<std::string> result;

    for (const auto& field : request) {
        if (!beast::iequals(field.name_string(), name)) {
            continue;
        }

        if (result.has_value()) {
            return std::string{};
        }

        const auto value = field.value();
        result = std::string(value.data(), value.size());
    }

    return result;
}

std::vector<std::string> split_csv(
    std::string_view value
) {
    std::vector<std::string> result;
    std::size_t start = 0;

    while (start <= value.size()) {
        const auto separator = value.find(',', start);
        const auto length =
            separator == std::string_view::npos
                ? value.size() - start
                : separator - start;

        result.push_back(
            trim_copy(value.substr(start, length))
        );

        if (separator == std::string_view::npos) {
            break;
        }

        start = separator + 1;
    }

    return result;
}

void prepare_middleware_response(
    HttpResponse& response,
    const HttpRequest& request
) {
    response.version(request.version());
    response.set(http::field::server, "SecureCore");
    response.keep_alive(request.keep_alive());
    response.prepare_payload();
}

void apply_security_headers(
    HttpResponse& response,
    const RequestContext& context,
    const HstsPolicy& hsts_policy
) {
    response.set(
        "X-Content-Type-Options",
        "nosniff"
    );

    response.set(
        "X-Frame-Options",
        "DENY"
    );

    response.set(
        "Referrer-Policy",
        "no-referrer"
    );

    response.set(
        "Permissions-Policy",
        "camera=(), microphone=(), geolocation=()"
    );

    response.set(
        "Content-Security-Policy",
        "default-src 'none'; frame-ancestors 'none'; base-uri 'none'"
    );

    response.set(
        http::field::cache_control,
        "no-store"
    );

    if (
        hsts_policy.enabled &&
        context.secure_transport
    ) {
        std::string value =
            "max-age=" +
            std::to_string(
                hsts_policy.max_age_seconds
            );

        if (hsts_policy.include_subdomains) {
            value += "; includeSubDomains";
        }

        if (hsts_policy.preload) {
            value += "; preload";
        }

        response.set(
            "Strict-Transport-Security",
            value
        );
    }
}

void apply_cors_headers(
    HttpResponse& response,
    const CorsPolicy& policy,
    std::string_view origin,
    bool preflight
) {
    if (policy.wildcard()) {
        response.set(
            "Access-Control-Allow-Origin",
            "*"
        );
    } else {
        response.set(
            "Access-Control-Allow-Origin",
            std::string(origin)
        );
        response.set(
            http::field::vary,
            preflight
                ? "Origin, Access-Control-Request-Method, Access-Control-Request-Headers"
                : "Origin"
        );
    }

    if (policy.allow_credentials()) {
        response.set(
            "Access-Control-Allow-Credentials",
            "true"
        );
    }

    response.set(
        "Access-Control-Allow-Methods",
        std::string(allowed_methods)
    );

    response.set(
        "Access-Control-Allow-Headers",
        std::string(allowed_headers)
    );

    response.set(
        "Access-Control-Expose-Headers",
        "X-Request-ID, X-RateLimit-Limit, X-RateLimit-Remaining, Retry-After"
    );

    response.set(
        "Access-Control-Max-Age",
        std::to_string(policy.max_age_seconds())
    );
}

bool allowed_preflight_method(
    std::string_view value
) {
    const std::string method = trim_copy(value);

    return std::any_of(
        allowed_method_values.begin(),
        allowed_method_values.end(),
        [&method](std::string_view allowed) {
            return method == allowed;
        }
    );
}

bool allowed_preflight_headers(
    std::string_view value
) {
    for (const std::string& item : split_csv(value)) {
        if (item.empty()) {
            return false;
        }

        const std::string normalized =
            lowercase_copy(item);

        const bool allowed = std::any_of(
            allowed_header_values.begin(),
            allowed_header_values.end(),
            [&normalized](std::string_view candidate) {
                return normalized == candidate;
            }
        );

        if (!allowed) {
            return false;
        }
    }

    return true;
}

HttpResponse make_internal_error_response(
    const HttpRequest& request
) {
    HttpResponse response =
        make_json_error(
            http::status::internal_server_error,
            "internal_server_error"
        );

    response.version(request.version());
    response.set(http::field::server, "SecureCore");
    response.keep_alive(false);
    response.prepare_payload();

    return response;
}

}  // namespace

void MiddlewarePipeline::use(
    Middleware middleware
) {
    if (!middleware) {
        throw std::invalid_argument(
            "Middleware must not be empty"
        );
    }

    middlewares_.push_back(
        std::move(middleware)
    );
}

HttpResponse MiddlewarePipeline::execute(
    const RequestContext& context,
    const Next& terminal_handler
) const {
    if (!terminal_handler) {
        throw std::invalid_argument(
            "Terminal handler must not be empty"
        );
    }

    return invoke(
        0,
        context,
        terminal_handler
    );
}

HttpResponse MiddlewarePipeline::invoke(
    std::size_t index,
    const RequestContext& context,
    const Next& terminal_handler
) const {
    if (index >= middlewares_.size()) {
        return terminal_handler();
    }

    const Next next = [
        this,
        index,
        &context,
        &terminal_handler
    ] {
        return invoke(
            index + 1,
            context,
            terminal_handler
        );
    };

    return middlewares_[index](
        context,
        next
    );
}

void register_default_middlewares(
    MiddlewarePipeline& pipeline,
    RateLimiter& rate_limiter,
    Logger& logger,
    MetricsRegistry& metrics_registry,
    const CorsPolicy& cors_policy,
    HstsPolicy hsts_policy
) {
    pipeline.use(
        [
            &logger,
            &metrics_registry
        ](
            const RequestContext& context,
            const MiddlewarePipeline::Next& next
        ) {
            const std::string request_id =
                resolve_request_id(
                    context.request
                );

            std::string user_agent;

            const auto user_agent_iterator =
                context.request.find(
                    http::field::user_agent
                );

            if (
                user_agent_iterator !=
                context.request.end()
            ) {
                const auto value =
                    user_agent_iterator->value();

                user_agent.assign(
                    value.data(),
                    value.size()
                );
            }

            ScopedRequestAuditContext audit_context{
                RequestAuditContext{
                    request_id,
                    context.client_ip,
                    std::move(user_agent)
                }
            };

            const auto started_at =
                std::chrono::steady_clock::now();

            HttpResponse response = next();

            const auto elapsed =
                std::chrono::duration_cast<
                    std::chrono::microseconds
                >(
                    std::chrono::steady_clock::now() -
                    started_at
                );

            metrics_registry.record_http_response(
                response.result_int(),
                elapsed
            );

            apply_request_id(
                response,
                request_id
            );

            logger.info(
                "HTTP ",
                context.request.method_string(),
                ' ',
                context.request.target(),
                " from ",
                context.client_ip,
                context.client_ip != context.peer_ip
                    ? " via proxy peer "
                    : "",
                context.client_ip != context.peer_ip
                    ? context.peer_ip
                    : "",
                " -> ",
                response.result_int(),
                " in ",
                elapsed.count() / 1000.0,
                "ms, request_id=",
                request_id,
                '.'
            );

            return response;
        }
    );

    pipeline.use(
        [hsts_policy](
            const RequestContext& context,
            const MiddlewarePipeline::Next& next
        ) {
            HttpResponse response = next();

            apply_security_headers(
                response,
                context,
                hsts_policy
            );

            return response;
        }
    );

    pipeline.use(
        [&cors_policy](
            const RequestContext& context,
            const MiddlewarePipeline::Next& next
        ) {
            const auto origin_header = request_header(
                context.request,
                "Origin"
            );

            if (
                origin_header.has_value() &&
                origin_header->empty()
            ) {
                HttpResponse response = make_json_error(
                    http::status::forbidden,
                    "cors_origin_denied"
                );
                prepare_middleware_response(
                    response,
                    context.request
                );
                return response;
            }

            const bool has_origin =
                origin_header.has_value();

            const std::string origin =
                has_origin
                    ? trim_copy(*origin_header)
                    : std::string{};

            if (
                has_origin &&
                (
                    origin.empty() ||
                    !cors_policy.allows(origin)
                )
            ) {
                HttpResponse response = make_json_error(
                    http::status::forbidden,
                    "cors_origin_denied"
                );
                prepare_middleware_response(
                    response,
                    context.request
                );
                return response;
            }

            const bool is_options =
                context.request.method() ==
                http::verb::options;

            const auto requested_method = request_header(
                context.request,
                "Access-Control-Request-Method"
            );

            const bool preflight =
                is_options &&
                has_origin &&
                requested_method.has_value();

            if (preflight) {
                const auto requested_headers = request_header(
                    context.request,
                    "Access-Control-Request-Headers"
                );

                if (
                    requested_method->empty() ||
                    !allowed_preflight_method(
                        *requested_method
                    ) ||
                    (
                        requested_headers.has_value() &&
                        (
                            requested_headers->empty() ||
                            !allowed_preflight_headers(
                                *requested_headers
                            )
                        )
                    )
                ) {
                    HttpResponse response = make_json_error(
                        http::status::forbidden,
                        "cors_preflight_denied"
                    );
                    prepare_middleware_response(
                        response,
                        context.request
                    );
                    apply_cors_headers(
                        response,
                        cors_policy,
                        origin,
                        true
                    );
                    return response;
                }
            }

            HttpResponse response;

            if (is_options) {
                response = HttpResponse{
                    http::status::no_content,
                    context.request.version()
                };
                response.set(
                    http::field::server,
                    "SecureCore"
                );
                response.keep_alive(
                    context.request.keep_alive()
                );
                response.prepare_payload();
            } else {
                response = next();
            }

            if (has_origin) {
                apply_cors_headers(
                    response,
                    cors_policy,
                    origin,
                    preflight
                );
            }

            return response;
        }
    );

    pipeline.use(
        [&logger](
            const RequestContext& context,
            const MiddlewarePipeline::Next& next
        ) {
            try {
                return next();
            } catch (const ApiException& error) {
                return make_api_error_response(
                    error.status(),
                    error.error()
                );
            } catch (const std::exception& error) {
                logger.error(
                    "Unhandled HTTP request exception from ",
                    context.client_ip,
                    ": ",
                    error.what()
                );

                return make_internal_error_response(
                    context.request
                );
            } catch (...) {
                logger.error(
                    "Unknown HTTP request exception from ",
                    context.client_ip,
                    '.'
                );

                return make_internal_error_response(
                    context.request
                );
            }
        }
    );

    pipeline.use(
        [
            &rate_limiter,
            &logger
        ](
            const RequestContext& context,
            const MiddlewarePipeline::Next& next
        ) {
            const RateLimitDecision decision =
                rate_limiter.check(
                    context.client_ip
                );

            if (!decision.allowed) {
                logger.warning(
                    "HTTP rate limit exceeded by ",
                    context.client_ip,
                    '.'
                );

                HttpResponse response = make_json_error(
                    http::status::too_many_requests,
                    "rate_limit_exceeded"
                );

                response.version(
                    context.request.version()
                );
                response.set(
                    http::field::server,
                    "SecureCore"
                );
                response.set(
                    http::field::retry_after,
                    std::to_string(
                        decision.retry_after.count()
                    )
                );
                response.set(
                    "X-RateLimit-Limit",
                    std::to_string(decision.limit)
                );
                response.set(
                    "X-RateLimit-Remaining",
                    "0"
                );
                response.keep_alive(false);
                response.prepare_payload();

                return response;
            }

            HttpResponse response = next();

            if (decision.limit != 0) {
                response.set(
                    "X-RateLimit-Limit",
                    std::to_string(decision.limit)
                );
                response.set(
                    "X-RateLimit-Remaining",
                    std::to_string(decision.remaining)
                );
            }

            return response;
        }
    );
}

}  // namespace secure
