#pragma once

#include "secure/http/http_limits.hpp"
#include "secure/http/http_types.hpp"
#include "secure/net/connection.hpp"

#include <cstddef>
#include <memory>
#include <optional>
#include <string_view>

#include <boost/asio/ip/tcp.hpp>
#include <boost/beast/core/flat_buffer.hpp>
#include <boost/beast/core/tcp_stream.hpp>
#include <boost/beast/http/parser.hpp>
#include <boost/system/error_code.hpp>

namespace secure {

class ConnectionManager;
class Logger;
class Router;

class HttpSession final
    : public Connection,
      public std::enable_shared_from_this<
          HttpSession
      > {
public:
    HttpSession(
        boost::asio::ip::tcp::socket socket,
        ConnectionManager& connection_manager,
        Logger& logger,
        Router& router,
        const HttpLimits& limits
    );

    void start() override;

    void stop() override;

private:
    using RequestParser =
        boost::beast::http::request_parser<
            boost::beast::http::string_body
        >;

    void do_read();

    void handle_read(
        const boost::system::error_code& error
    );

    void handle_request();

    void send_response(
        HttpResponse response
    );

    void send_protocol_error(
        boost::beast::http::status status,
        std::string_view error_code
    );

    void handle_disconnect(
        const boost::system::error_code& error
    );

    boost::beast::tcp_stream stream_;

    ConnectionManager& connection_manager_;

    Logger& logger_;

    Router& router_;

    const HttpLimits& limits_;

    boost::beast::flat_buffer buffer_;

    std::optional<RequestParser> parser_;

    HttpRequest request_;

    std::size_t completed_requests_{0};

    bool stopped_{false};
};

}  // namespace secure
