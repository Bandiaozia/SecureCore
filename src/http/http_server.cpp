#include "secure/http/http_server.hpp"

#include "secure/http/http_session.hpp"
#include "secure/http/http_types.hpp"
#include "secure/http/middleware.hpp"
#include "secure/http/router.hpp"
#include "secure/http/tls_http_session.hpp"
#include "secure/log/logger.hpp"
#include "secure/observability/metrics_registry.hpp"
#include "secure/runtime/worker_pool.hpp"

#include <chrono>
#include <cstddef>
#include <future>
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
    boost::asio::ssl::context* tls_context,
    Logger& logger,
    Router& router,
    MiddlewarePipeline& middleware_pipeline,
    WorkerPool& worker_pool,
    MetricsRegistry& metrics_registry,
    HttpLimits limits
)
    : tls_context_(tls_context),
      logger_(logger),
      router_(router),
      middleware_pipeline_(middleware_pipeline),
      worker_pool_(worker_pool),
      metrics_registry_(metrics_registry),
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
        protocol_name(),
        " server configured on ",
        listen_address,
        ':',
        port,
        '.'
    );

    logger_.info(
        "Maximum ",
        protocol_name(),
        " connections: ",
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
        "s, tls_handshake_timeout=",
        limits_.tls_handshake_timeout.count(),
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
                protocol_name(),
                " server started."
            );

            do_accept();
        }
    );
}

void HttpServer::begin_draining() {
    boost::asio::dispatch(
        strand_,
        [this] {
            do_begin_draining();
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

bool HttpServer::force_stop_and_wait(
    std::chrono::milliseconds timeout
) {
    const auto deadline =
        std::chrono::steady_clock::now() +
        timeout;

    auto completion =
        std::make_shared<std::promise<void>>();

    std::future<void> finished =
        completion->get_future();

    boost::asio::dispatch(
        strand_,
        [
            this,
            completion
        ] {
            do_stop();
            completion->set_value();
        }
    );

    if (
        finished.wait_until(deadline) !=
        std::future_status::ready
    ) {
        return false;
    }

    const auto now =
        std::chrono::steady_clock::now();

    if (now >= deadline) {
        return connection_manager_.size() == 0;
    }

    return connection_manager_.wait_until_empty(
        std::chrono::duration_cast<
            std::chrono::milliseconds
        >(deadline - now)
    );
}

bool HttpServer::wait_until_idle(
    std::chrono::milliseconds timeout
) const {
    return connection_manager_.wait_until_empty(
        timeout
    );
}

std::size_t HttpServer::active_connections()
    const {
    return connection_manager_.size();
}

void HttpServer::close_acceptor() {
    boost::system::error_code error;

    acceptor_.cancel(error);

    error.clear();

    acceptor_.close(error);

    if (
        error &&
        error != boost::asio::error::bad_descriptor
    ) {
        logger_.error(
            "Failed to close ",
            protocol_name(),
            " acceptor: ",
            error.message()
        );
    }
}

void HttpServer::do_begin_draining() {
    if (draining_ || stopped_) {
        return;
    }

    draining_ = true;
    close_acceptor();

    connection_manager_.drain_all();

    logger_.info(
        protocol_name(),
        " server stopped accepting new "
        "connections. Draining ",
        connection_manager_.size(),
        " active connection(s)."
    );
}

void HttpServer::do_stop() {
    if (stopped_) {
        return;
    }

    draining_ = true;
    stopped_ = true;

    close_acceptor();
    connection_manager_.stop_all();

    logger_.info(
        "All ",
        protocol_name(),
        " connections stopped."
    );
}

void HttpServer::reject_connection(
    tcp::socket socket
) {
    namespace beast = boost::beast;
    namespace http = beast::http;

    /*
     * HTTPS 客户端在 TLS 握手之前不能接收
     * 普通 HTTP 503 响应，因此直接关闭连接。
     */
    if (tls_context_ != nullptr) {
        boost::system::error_code ignored_error;

        socket.shutdown(
            tcp::socket::shutdown_both,
            ignored_error
        );

        socket.close(ignored_error);

        return;
    }

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

                boost::system::error_code
                    ignored_error;

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
        draining_ ||
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
                    !stopped_ &&
                    !draining_
                ) {
                    if (
                        connection_manager_.full()
                    ) {
                        logger_.warning(
                            protocol_name(),
                            " connection limit reached: ",
                            connection_manager_.capacity(),
                            ". Rejecting client."
                        );

                        reject_connection(
                            std::move(socket)
                        );
                    } else {
                        std::shared_ptr<Connection>
                            session;

                        if (tls_context_ != nullptr) {
                            session =
                                std::make_shared<
                                    TlsHttpSession
                                >(
                                    std::move(socket),
                                    *tls_context_,
                                    connection_manager_,
                                    logger_,
                                    router_,
                                    middleware_pipeline_,
                                    worker_pool_,
                                    metrics_registry_,
                                    limits_
                                );
                        } else {
                            session =
                                std::make_shared<
                                    HttpSession
                                >(
                                    std::move(socket),
                                    connection_manager_,
                                    logger_,
                                    router_,
                                    middleware_pipeline_,
                                    worker_pool_,
                                    metrics_registry_,
                                    limits_
                                );
                        }

                        if (
                            connection_manager_.start(
                                session
                            )
                        ) {
                            logger_.info(
                                "Active ",
                                protocol_name(),
                                " connections: ",
                                connection_manager_.size()
                            );
                        } else {
                            session->stop();

                            logger_.warning(
                                protocol_name(),
                                " connection could not "
                                "be registered."
                            );
                        }
                    }
                } else if (
                    !error &&
                    (stopped_ || draining_)
                ) {
                    boost::system::error_code
                        ignored_error;

                    socket.shutdown(
                        tcp::socket::shutdown_both,
                        ignored_error
                    );

                    socket.close(ignored_error);
                } else if (
                    error &&
                    error !=
                        boost::asio::error::
                            operation_aborted &&
                    !stopped_ &&
                    !draining_
                ) {
                    logger_.error(
                        protocol_name(),
                        " accept failed: ",
                        error.message()
                    );
                }

                if (
                    !stopped_ &&
                    !draining_ &&
                    acceptor_.is_open()
                ) {
                    do_accept();
                }
            }
        )
    );
}

const char* HttpServer::protocol_name()
    const noexcept {
    return tls_context_ == nullptr
        ? "HTTP"
        : "HTTPS";
}

}  // namespace secure
