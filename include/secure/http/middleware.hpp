#pragma once

#include "secure/http/http_types.hpp"

#include <cstddef>
#include <functional>
#include <string>
#include <vector>

namespace secure {

class Logger;
class RateLimiter;

struct RequestContext final {
    const HttpRequest& request;

    const std::string& client_ip;
};

class MiddlewarePipeline final {
public:
    using Next =
        std::function<HttpResponse()>;

    using Middleware =
        std::function<
            HttpResponse(
                const RequestContext&,
                const Next&
            )
        >;

    void use(
        Middleware middleware
    );

    [[nodiscard]]
    HttpResponse execute(
        const RequestContext& context,
        const Next& terminal_handler
    ) const;

private:
    [[nodiscard]]
    HttpResponse invoke(
        std::size_t index,
        const RequestContext& context,
        const Next& terminal_handler
    ) const;

    std::vector<Middleware>
        middlewares_;
};

void register_default_middlewares(
    MiddlewarePipeline& pipeline,
    RateLimiter& rate_limiter,
    Logger& logger
);

}  // namespace secure
