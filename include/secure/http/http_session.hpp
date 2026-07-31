#pragma once

#include "secure/http/http_types.hpp"
#include "secure/net/connection.hpp"

#include <memory>

#include <boost/asio/ip/tcp.hpp>
#include <boost/beast/core/flat_buffer.hpp>
#include <boost/system/error_code.hpp>

namespace secure {

class ConnectionManager;
class Logger;
class Router;

class HttpSession final
    : public Connection,
      public std::enable_shared_from_this<HttpSession> {
public:
    HttpSession(
        boost::asio::ip::tcp::socket socket,
        ConnectionManager& connection_manager,
        Logger& logger,
        Router& router
    );

    void start() override;

    void stop() override;

private:
    void do_read();

    void handle_request();

    void send_response(
        HttpResponse response
    );

    void handle_disconnect(
        const boost::system::error_code& error
    );

    boost::asio::ip::tcp::socket socket_;

    ConnectionManager& connection_manager_;

    Logger& logger_;

    Router& router_;

    boost::beast::flat_buffer buffer_;

    HttpRequest request_;

    bool stopped_{false};
};

}  // namespace secure
