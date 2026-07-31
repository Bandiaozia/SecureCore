#pragma once

#include <memory>

#include <boost/asio/ip/tcp.hpp>
#include <boost/beast/core/flat_buffer.hpp>
#include <boost/beast/http.hpp>
#include <boost/system/error_code.hpp>

#include "secure/net/connection.hpp"

namespace secure {

class ConnectionManager;
class Logger;

class HttpSession final
    : public Connection,
      public std::enable_shared_from_this<HttpSession> {
public:
    HttpSession(
        boost::asio::ip::tcp::socket socket,
        ConnectionManager& connection_manager,
        Logger& logger
    );

    void start() override;

    void stop() override;

private:
    using Request =
        boost::beast::http::request<
            boost::beast::http::string_body
        >;

    using Response =
        boost::beast::http::response<
            boost::beast::http::string_body
        >;

    void do_read();

    void handle_request();

    void send_response(Response response);

    void handle_disconnect(
        const boost::system::error_code& error
    );

    boost::asio::ip::tcp::socket socket_;

    ConnectionManager& connection_manager_;

    Logger& logger_;

    boost::beast::flat_buffer buffer_;

    Request request_;

    bool stopped_{false};
};

}  // namespace secure
