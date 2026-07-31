#pragma once

#include <boost/asio/io_context.hpp>
#include <boost/asio/signal_set.hpp>

#include "secure/config/server_config.hpp"
#include "secure/net/tcp_server.hpp"

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

    boost::asio::io_context io_context_;
    boost::asio::signal_set signals_;

    TcpServer tcp_server_;
};

}  // namespace secure