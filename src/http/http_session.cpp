#include "secure/http/http_session.hpp"

#include "secure/log/logger.hpp"
#include "secure/net/connection_manager.hpp"

#include <memory>
#include <utility>

#include <boost/asio/error.hpp>
#include <boost/beast/http.hpp>

namespace secure {

namespace beast = boost::beast;
namespace http = beast::http;
using boost::asio::ip::tcp;

HttpSession::HttpSession(
    tcp::socket socket,
    ConnectionManager& connection_manager,
    Logger& logger
)
    : socket_(std::move(socket)),
      connection_manager_(connection_manager),
      logger_(logger) {
}

void HttpSession::start() {
    logger_.info("HTTP session started.");
    do_read();
}

void HttpSession::stop() {
    if (stopped_) {
        return;
    }

    stopped_ = true;

    boost::system::error_code ignored_error;

    socket_.cancel(ignored_error);

    socket_.shutdown(
        tcp::socket::shutdown_both,
        ignored_error
    );

    socket_.close(ignored_error);
}

void HttpSession::do_read() {
    request_ = {};

    auto self = shared_from_this();

    http::async_read(
        socket_,
        buffer_,
        request_,
        [self](
            const boost::system::error_code& error,
            std::size_t
        ) {
            if (error) {
                self->handle_disconnect(error);
                return;
            }

            self->handle_request();
        }
    );
}

void HttpSession::handle_request() {
    logger_.debug(
        "HTTP request: ",
        request_.method_string(),
        ' ',
        request_.target()
    );

    Response response{
        http::status::ok,
        request_.version()
    };

    response.set(
        http::field::server,
        "SecureCore"
    );

    response.set(
        http::field::content_type,
        "application/json"
    );

    response.keep_alive(
        request_.keep_alive()
    );

    if (request_.target() == "/health") {
        if (request_.method() != http::verb::get) {
            response.result(
                http::status::method_not_allowed
            );

            response.set(
                http::field::allow,
                "GET"
            );

            response.body() =
                R"({"error":"method_not_allowed"})";
        } else {
            response.result(http::status::ok);

            response.body() =
                R"({"status":"ok"})";
        }
    } else {
        response.result(
            http::status::not_found
        );

        response.body() =
            R"({"error":"not_found"})";
    }

    response.prepare_payload();

    send_response(std::move(response));
}

void HttpSession::send_response(
    Response response
) {
    const bool should_close =
        response.need_eof();

    auto shared_response =
        std::make_shared<Response>(
            std::move(response)
        );

    auto self = shared_from_this();

    http::async_write(
        socket_,
        *shared_response,
        [
            self,
            shared_response,
            should_close
        ](
            const boost::system::error_code& error,
            std::size_t
        ) {
            if (error) {
                self->handle_disconnect(error);
                return;
            }

            if (should_close) {
                self->handle_disconnect({});
                return;
            }

            self->do_read();
        }
    );
}

void HttpSession::handle_disconnect(
    const boost::system::error_code& error
) {
    if (stopped_) {
        return;
    }

    if (
        error &&
        error != http::error::end_of_stream &&
        error != boost::asio::error::eof &&
        error !=
            boost::asio::error::operation_aborted
    ) {
        logger_.warning(
            "HTTP connection ended with error: ",
            error.message()
        );
    }

    stop();

    connection_manager_.remove(
        shared_from_this()
    );

    logger_.info(
        "HTTP client disconnected. Active connections: ",
        connection_manager_.size()
    );
}

}  // namespace secure
