#include "secure/http/middleware.hpp"

#include "secure/http/json_utils.hpp"
#include "secure/http/rate_limiter.hpp"
#include "secure/log/logger.hpp"
#include "secure/observability/metrics_registry.hpp"

#include <atomic>
#include <chrono>
#include <cctype>
#include <cstdint>
#include <exception>
#include <sstream>
#include <stdexcept>
#include <string>
#include <utility>

#include <boost/beast/http.hpp>

namespace secure {

namespace http = boost::beast::http;

namespace {

std::atomic<std::uint64_t>
    request_sequence{0};

bool is_valid_request_id_character(
    char character
) {
    const auto value =
        static_cast<unsigned char>(
            character
        );

    return (
        std::isalnum(value) != 0 ||
        character == '-' ||
        character == '_' ||
        character == '.'
    );
}

bool is_valid_request_id(
    const std::string& request_id
) {
    if (
        request_id.empty() ||
        request_id.size() > 64
    ) {
        return false;
    }

    for (const char character : request_id) {
        if (
            !is_valid_request_id_character(
                character
            )
        ) {
            return false;
        }
    }

    return true;
}

std::string generate_request_id() {
    const auto timestamp =
        std::chrono::duration_cast<
            std::chrono::nanoseconds
        >(
            std::chrono::steady_clock::
                now().time_since_epoch()
        ).count();

    const auto sequence =
        request_sequence.fetch_add(
            1,
            std::memory_order_relaxed
        );

    std::ostringstream stream;

    stream
        << std::hex
        << static_cast<std::uint64_t>(
            timestamp
        )
        << '-'
        << sequence;

    return stream.str();
}

std::string resolve_request_id(
    const HttpRequest& request
) {
    const auto iterator =
        request.find("X-Request-ID");

    if (iterator != request.end()) {
        const auto value =
            iterator->value();

        std::string request_id(
            value.data(),
            value.size()
        );

        if (is_valid_request_id(request_id)) {
            return request_id;
        }
    }

    return generate_request_id();
}

void apply_security_headers(
    HttpResponse& response
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
        "camera=(), microphone=(), "
        "geolocation=()"
    );

    response.set(
        "Content-Security-Policy",
        "default-src 'none'; "
        "frame-ancestors 'none'; "
        "base-uri 'none'"
    );

    response.set(
        http::field::cache_control,
        "no-store"
    );
}

void apply_cors_headers(
    HttpResponse& response
) {
    response.set(
        "Access-Control-Allow-Origin",
        "*"
    );

    response.set(
        "Access-Control-Allow-Methods",
        "GET, POST, PUT, PATCH, DELETE, OPTIONS"
    );

    response.set(
        "Access-Control-Allow-Headers",
        "Authorization, Content-Type, "
        "X-Request-ID"
    );

    response.set(
        "Access-Control-Expose-Headers",
        "X-Request-ID, "
        "X-RateLimit-Limit, "
        "X-RateLimit-Remaining, "
        "Retry-After"
    );

    response.set(
        "Access-Control-Max-Age",
        "600"
    );
}

HttpResponse make_internal_error_response(
    const HttpRequest& request
) {
    HttpResponse response =
        make_json_error(
            http::status::
                internal_server_error,
            "internal_server_error"
        );

    response.version(
        request.version()
    );

    response.set(
        http::field::server,
        "SecureCore"
    );

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
    MetricsRegistry& metrics_registry
) {
    /*
     * 请求 ID 与访问日志。
     *
     * 放在最外层，确保正常响应、429、404 和 500
     * 都能获得 X-Request-ID。
     */
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

            const auto started_at =
                std::chrono::steady_clock::now();

            HttpResponse response = next();

            const auto elapsed =
                std::chrono::duration_cast<
                    std::chrono::microseconds
                >(
                    std::chrono::steady_clock::now()
                    - started_at
                );

            metrics_registry.record_http_response(
                response.result_int(),
                elapsed
            );

            response.set(
                "X-Request-ID",
                request_id
            );

            logger.info(
                "HTTP ",
                context.request.method_string(),
                ' ',
                context.request.target(),
                " from ",
                context.client_ip,
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

    /*
     * 安全响应头。
     *
     * 位于异常处理中间件外层，所以 500 响应
     * 同样会携带安全响应头。
     */
    pipeline.use(
        [](
            const RequestContext& context,
            const MiddlewarePipeline::Next& next
        ) {
            static_cast<void>(context);

            HttpResponse response = next();

            apply_security_headers(
                response
            );

            return response;
        }
    );

    /*
     * CORS 与浏览器 OPTIONS 预检。
     */
    pipeline.use(
        [](
            const RequestContext& context,
            const MiddlewarePipeline::Next& next
        ) {
            HttpResponse response;

            if (
                context.request.method() ==
                http::verb::options
            ) {
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

            apply_cors_headers(
                response
            );

            return response;
        }
    );

    /*
     * 统一异常处理。
     *
     * Router 或后续中间件抛出异常时，
     * 统一转成 JSON 500 响应。
     */
    pipeline.use(
        [&logger](
            const RequestContext& context,
            const MiddlewarePipeline::Next& next
        ) {
            try {
                return next();
            } catch (
                const std::exception& error
            ) {
                logger.error(
                    "Unhandled HTTP request exception "
                    "from ",
                    context.client_ip,
                    ": ",
                    error.what()
                );

                return make_internal_error_response(
                    context.request
                );
            } catch (...) {
                logger.error(
                    "Unknown HTTP request exception "
                    "from ",
                    context.client_ip,
                    '.'
                );

                return make_internal_error_response(
                    context.request
                );
            }
        }
    );

    /*
     * IP 固定窗口限流。
     */
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

                HttpResponse response =
                    make_json_error(
                        http::status::
                            too_many_requests,
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
                        decision
                            .retry_after
                            .count()
                    )
                );

                response.set(
                    "X-RateLimit-Limit",
                    std::to_string(
                        decision.limit
                    )
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
                    std::to_string(
                        decision.limit
                    )
                );

                response.set(
                    "X-RateLimit-Remaining",
                    std::to_string(
                        decision.remaining
                    )
                );
            }

            return response;
        }
    );
}

}  // namespace secure
