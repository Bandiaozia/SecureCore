#pragma once

#include "secure/config/server_config.hpp"
#include "secure/http/http_server.hpp"
#include "secure/http/middleware.hpp"
#include "secure/http/rate_limiter.hpp"
#include "secure/http/router.hpp"
#include "secure/log/logger.hpp"

#include <atomic>

#include <boost/asio/io_context.hpp>
#include <boost/asio/signal_set.hpp>

namespace secure {

class ServerApplication final {
public:
    explicit ServerApplication(
        ServerConfig config
    );

    int run();

private:
    void run_io_context();

    void stop();

    ServerConfig config_;

    Logger logger_;

    Router router_;

    RateLimiter rate_limiter_;

    MiddlewarePipeline middleware_pipeline_;

    boost::asio::io_context io_context_;

    boost::asio::signal_set signals_;

    HttpServer http_server_;

    std::atomic_bool stopping_{false};
};

}  // namespace secure
