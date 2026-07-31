#include "secure/http/middleware.hpp"

#include "secure/http/json_utils.hpp"
#include "secure/http/rate_limiter.hpp"
#include "secure/log/logger.hpp"

#include <stdexcept>
#include <string>
#include <utility>

#include <boost/beast/http.hpp>

namespace secure {

namespace http = boost::beast::http;

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
    Logger& logger
) {
    pipeline.use(
        [&logger](
            const RequestContext& context,
            const MiddlewarePipeline::Next& next
        ) {
            logger.debug(
                "HTTP request from ",
                context.client_ip,
                ": ",
                context.request.method_string(),
                ' ',
                context.request.target()
            );

            return next();
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
