#pragma once

#include "secure/http/http_limits.hpp"
#include "secure/net/connection_manager.hpp"

#include <cstdint>
#include <string>

#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>

namespace secure {

class Logger;
class Router;

class HttpServer final {
public:
    HttpServer(
        boost::asio::io_context& io_context,
        const std::string& listen_address,
        std::uint16_t port,
        Logger& logger,
        Router& router,
        HttpLimits limits
    );

    void start();

    void stop();

private:
    void do_accept();

    Logger& logger_;

    Router& router_;

    HttpLimits limits_;

    ConnectionManager connection_manager_;

    boost::asio::ip::tcp::acceptor acceptor_;
};

}  // namespace secure
