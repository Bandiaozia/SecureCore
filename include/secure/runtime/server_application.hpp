#pragma once

#include <boost/asio/io_context.hpp>
#include <boost/asio/signal_set.hpp>

#include "secure/config/server_config.hpp"
#include "secure/http/http_server.hpp"
#include "secure/http/router.hpp"
#include "secure/log/logger.hpp"

namespace secure {

class ServerApplication final {
public:
    explicit ServerApplication(
        ServerConfig config
    );

    int run();

private:
    void stop();

    ServerConfig config_;

    Logger logger_;

    Router router_;

    boost::asio::io_context io_context_;

    boost::asio::signal_set signals_;

    HttpServer http_server_;
};

}  // namespace secure
