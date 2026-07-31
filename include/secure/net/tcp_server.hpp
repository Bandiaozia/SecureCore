#pragma once

#include <cstdint>
#include <string>

#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>

#include "secure/net/connection_manager.hpp"

namespace secure {

class Logger;

class TcpServer final {
public:
    TcpServer(
        boost::asio::io_context& io_context,
        const std::string& listen_address,
        std::uint16_t port,
        Logger& logger
    );

    void start();

    void stop();

private:
    void do_accept();

    Logger& logger_;

    ConnectionManager connection_manager_;

    boost::asio::ip::tcp::acceptor acceptor_;
};

}  // namespace secure
