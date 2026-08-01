#include "secure/http/http_server.hpp"

#include "secure/http/http_session.hpp"
#include "secure/http/http_types.hpp"
#include "secure/http/middleware.hpp"
#include "secure/http/router.hpp"
#include "secure/log/logger.hpp"
#include "secure/runtime/worker_pool.hpp"

#include <cstddef>
#include <memory>
#include <utility>

#include <boost/asio/bind_executor.hpp>
#include <boost/asio/dispatch.hpp>
#include <boost/asio/error.hpp>
#include <boost/asio/ip/address.hpp>
#include <boost/beast/core/tcp_stream.hpp>
#include <boost/beast/http.hpp>

namespace secure {

using boost::asio::ip::tcp;

HttpServer::HttpServer(
    boost::asio::io_context& io_context,
    const std::string& listen_address,
    std::uint16_t port,
    Logger& logger,
    Router& router,
    MiddlewarePipeline& middleware_pipeline,
    WorkerPool& worker_pool,
    HttpLimits limits
)
    : logger_(logger),
      router_(router),
      middleware_pipeline_(middleware_pipeline),
      worker_pool_(worker_pool),
      limits_(std::move(limits)),
      connection_manager_(
          limits_.max_connections
      ),
      strand_(
          boost::asio::make_strand(io_context)
      ),
      acceptor_(io_context) {
    const auto address =
        boost::asio::ip::make_address(
            listen_address
        );

    const tcp::endpoint endpoint(
        address,
        port
    );

    acceptor_.open(
        endpoint.protocol()
    );

    acceptor_.set_option(
        tcp::acceptor::reuse_address(true)
    );

    acceptor_.bind(endpoint);

    acceptor_.listen(
        tcp::acceptor::max_listen_connections
    );

    logger_.info(
        "HTTP server configured on ",
        listen_address,
        ':',
        port,
        '.'
    );

    logger_.info(
        "Maximum HTTP connections: ",
        limits_.max_connections,
        '.'
    );

    logger_.info(
        "HTTP limits: header=",
        limits_.max_header_bytes,
        " bytes, body=",
        limits_.max_body_bytes,
        " bytes, read_timeout=",
        limits_.read_timeout.count(),
        "s, write_timeout=",
        limits_.write_timeout.count(),
        "s, idle_timeout=",
        limits_.idle_timeout.count(),
        "s."
    );
}

void HttpServer::start() {
    boost::asio::dispatch(
        strand_,
        [this] {
            if (stopped_) {
                return;
            }

            logger_.info(
                "HTTP server started."
            );

            do_accept();
        }
    );
}

void HttpServer::stop() {
    boost::asio::dispatch(
        strand_,
        [this] {
            do_stop();
        }
    );
}

void HttpServer::do_stop() {
    if (stopped_) {
        return;
    }

    stopped_ = true;

    boost::system::error_code error;

    acceptor_.cancel(error);

    error.clear();

    acceptor_.close(error);

    if (
        error &&
        error != boost::asio::error::bad_descriptor
    ) {
        logger_.error(
            "Failed to close HTTP acceptor: ",
            error.message()
        );
    }

    connection_manager_.stop_all();

    logger_.info(
        "All HTTP connections stopped."
    );
}

void HttpServer::reject_connection(
    tcp::socket socket
) {
    namespace beast = boost::beast;
    namespace http = beast::http;

    auto stream =
        std::make_shared<beast::tcp_stream>(
            std::move(socket)
        );

    auto response =
        std::make_shared<HttpResponse>(
            http::status::service_unavailable,
            11
        );

    response->set(
        http::field::server,
        "SecureCore"
    );

    response->set(
        http::field::content_type,
        "application/json; charset=utf-8"
    );

    response->set(
        http::field::retry_after,
        "1"
    );

    response->keep_alive(false);

    response->body() =
        R"({"error":"connection_limit_reached"})";

    response->prepare_payload();

    stream->expires_after(
        limits_.write_timeout
    );

    http::async_write(
        *stream,
        *response,
        boost::asio::bind_executor(
            strand_,
            [
                stream,
                response
            ](
                const boost::system::error_code&,
                std::size_t
            ) {
                static_cast<void>(response);

                boost::system::error_code ignored_error;

                stream->socket().shutdown(
                    tcp::socket::shutdown_both,
                    ignored_error
                );

                stream->socket().close(
                    ignored_error
                );
            }
        )
    );
}

void HttpServer::do_accept() {
    if (
        stopped_ ||
        !acceptor_.is_open()
    ) {
        return;
    }

    acceptor_.async_accept(
        boost::asio::bind_executor(
            strand_,
            [this](
                const boost::system::error_code& error,
                tcp::socket socket
            ) {
                if (
                    !error &&
                    !stopped_
                ) {
                    if (
                        connection_manager_.full()
                    ) {
                        logger_.warning(
                            "HTTP connection limit reached: ",
                            connection_manager_.capacity(),
                            ". Rejecting client."
                        );

                        reject_connection(
                            std::move(socket)
                        );
                    } else {
                        auto session =
                            std::make_shared<HttpSession>(
                                std::move(socket),
                                connection_manager_,
                                logger_,
                                router_,
                                middleware_pipeline_,
                                worker_pool_,
                                limits_
                            );

                        if (
                            connection_manager_.start(
                                session
                            )
                        ) {
                            logger_.info(
                                "Active HTTP connections: ",
                                connection_manager_.size()
                            );
                        } else {
                            session->stop();

                            logger_.warning(
                                "HTTP connection could not "
                                "be registered."
                            );
                        }
                    }
                } else if (
                    error &&
                    error !=
                        boost::asio::error::
                            operation_aborted &&
                    !stopped_
                ) {
                    logger_.error(
                        "HTTP accept failed: ",
                        error.message()
                    );
                }

                if (
                    !stopped_ &&
                    acceptor_.is_open()
                ) {
                    do_accept();
                }
            }
        )
    );
}

}  // namespace secure
