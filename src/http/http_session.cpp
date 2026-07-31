#include "secure/http/http_session.hpp"
#include "secure/http/http_types.hpp"
#include "secure/http/json_utils.hpp"
#include "secure/http/router.hpp"
#include "secure/log/logger.hpp"
#include "secure/net/connection_manager.hpp"

#include <exception>
#include <memory>
#include <utility>

#include <boost/asio/bind_executor.hpp>
#include <boost/asio/dispatch.hpp>
#include <boost/asio/error.hpp>
#include <boost/beast/core/error.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/core/tcp_stream.hpp>
#include <boost/beast/http.hpp>

namespace secure {

namespace beast = boost::beast;
namespace http = beast::http;

using boost::asio::ip::tcp;

HttpSession::HttpSession(
    tcp::socket socket,
    ConnectionManager& connection_manager,
    Logger& logger,
    Router& router,
    const HttpLimits& limits
)
    : stream_(std::move(socket)),
      strand_(
          boost::asio::make_strand(
              stream_.get_executor()
          )
      ),
      connection_manager_(connection_manager),
      logger_(logger),
      router_(router),
      limits_(limits) {
}

void HttpSession::start() {
    auto self = shared_from_this();

    boost::asio::dispatch(
        strand_,
        [self] {
            self->do_start();
        }
    );
}

void HttpSession::stop() {
    auto self = shared_from_this();

    boost::asio::dispatch(
        strand_,
        [self] {
            self->do_stop();
        }
    );
}

void HttpSession::do_start() {
    if (
        started_ ||
        stopped_
    ) {
        return;
    }

    started_ = true;

    logger_.info(
        "HTTP session started."
    );

    do_read();
}

void HttpSession::do_stop() {
    if (stopped_) {
        return;
    }

    stopped_ = true;

    boost::system::error_code ignored_error;

    stream_.socket().cancel(
        ignored_error
    );

    stream_.socket().shutdown(
        tcp::socket::shutdown_both,
        ignored_error
    );

    stream_.socket().close(
        ignored_error
    );
}

void HttpSession::do_read() {
    if (stopped_) {
        return;
    }

    parser_.emplace();

    parser_->header_limit(
        limits_.max_header_bytes
    );

    parser_->body_limit(
        limits_.max_body_bytes
    );

    const auto timeout =
        completed_requests_ == 0
            ? limits_.read_timeout
            : limits_.idle_timeout;

    stream_.expires_after(timeout);

    auto self = shared_from_this();

    http::async_read(
        stream_,
        buffer_,
        *parser_,
        boost::asio::bind_executor(
            strand_,
            [self](
                const boost::system::error_code& error,
                std::size_t
            ) {
                self->handle_read(error);
            }
        )
    );
}

void HttpSession::handle_read(
    const boost::system::error_code& error
) {
    if (stopped_) {
        return;
    }

    if (!error) {
        request_ = parser_->release();

        parser_.reset();

        ++completed_requests_;

        handle_request();

        return;
    }

    parser_.reset();

    if (error == http::error::body_limit) {
        send_protocol_error(
            http::status::payload_too_large,
            "payload_too_large"
        );

        return;
    }

    if (error == http::error::header_limit) {
        send_protocol_error(
            http::status::
                request_header_fields_too_large,
            "headers_too_large"
        );

        return;
    }

    if (error == beast::error::timeout) {
        logger_.warning(
            "HTTP read timeout."
        );

        handle_disconnect({});

        return;
    }

    handle_disconnect(error);
}

void HttpSession::handle_request() {
    logger_.debug(
        "HTTP request: ",
        request_.method_string(),
        ' ',
        request_.target()
    );

    try {
        send_response(
            router_.dispatch(request_)
        );
    } catch (
        const std::exception& error
    ) {
        logger_.error(
            "Unhandled HTTP handler exception: ",
            error.what()
        );

        HttpResponse response =
            make_json_error(
                http::status::
                    internal_server_error,
                "internal_server_error"
            );

        response.version(
            request_.version()
        );

        response.set(
            http::field::server,
            "SecureCore"
        );

        response.keep_alive(false);

        response.prepare_payload();

        send_response(
            std::move(response)
        );
    }
}

void HttpSession::send_response(
    HttpResponse response
) {
    if (stopped_) {
        return;
    }

    const bool should_close =
        response.need_eof();

    auto shared_response =
        std::make_shared<HttpResponse>(
            std::move(response)
        );

    stream_.expires_after(
        limits_.write_timeout
    );

    auto self = shared_from_this();

    http::async_write(
        stream_,
        *shared_response,
        boost::asio::bind_executor(
            strand_,
            [
                self,
                shared_response,
                should_close
            ](
                const boost::system::error_code& error,
                std::size_t
            ) {
                static_cast<void>(
                    shared_response
                );

                if (self->stopped_) {
                    return;
                }

                if (error) {
                    if (
                        error ==
                        beast::error::timeout
                    ) {
                        self->logger_.warning(
                            "HTTP write timeout."
                        );

                        self->handle_disconnect(
                            {}
                        );

                        return;
                    }

                    self->handle_disconnect(
                        error
                    );

                    return;
                }

                if (should_close) {
                    self->handle_disconnect(
                        {}
                    );

                    return;
                }

                self->do_read();
            }
        )
    );
}

void HttpSession::send_protocol_error(
    http::status status,
    std::string_view error_code
) {
    logger_.warning(
        "Rejected HTTP request: ",
        error_code,
        '.'
    );

    HttpResponse response =
        make_json_error(
            status,
            error_code
        );

    response.version(11);

    response.set(
        http::field::server,
        "SecureCore"
    );

    response.keep_alive(false);

    response.prepare_payload();

    send_response(
        std::move(response)
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
            boost::asio::error::operation_aborted &&
        error != beast::error::timeout
    ) {
        logger_.warning(
            "HTTP connection ended with error: ",
            error.message()
        );
    }

    do_stop();

    connection_manager_.remove(
        shared_from_this()
    );

    logger_.info(
        "HTTP client disconnected. Active connections: ",
        connection_manager_.size()
    );
}

}  // namespace secure
