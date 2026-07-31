#pragma once

#include "secure/http/http_limits.hpp"
#include "secure/net/connection_manager.hpp"

#include <cstdint>
#include <string>

#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/strand.hpp>

namespace secure {

class Logger;
class MiddlewarePipeline;
class Router;

class HttpServer final {
public:
    HttpServer(
        boost::asio::io_context& io_context,
        const std::string& listen_address,
        std::uint16_t port,
        Logger& logger,
        Router& router,
        MiddlewarePipeline& middleware_pipeline,
        HttpLimits limits
    );

    void start();

    void stop();

private:
    void do_accept();

    void reject_connection(
        boost::asio::ip::tcp::socket socket
    );

    void do_stop();

    Logger& logger_;

    Router& router_;

    MiddlewarePipeline& middleware_pipeline_;

    HttpLimits limits_;

    ConnectionManager connection_manager_;

    boost::asio::strand<
        boost::asio::io_context::executor_type
    > strand_;

    boost::asio::ip::tcp::acceptor acceptor_;

    bool stopped_{false};
};

}  // namespace secure
