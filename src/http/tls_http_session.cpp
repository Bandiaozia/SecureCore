#include "secure/http/tls_http_session.hpp"

#include "secure/http/json_utils.hpp"
#include "secure/http/middleware.hpp"
#include "secure/http/router.hpp"
#include "secure/log/logger.hpp"
#include "secure/net/connection_manager.hpp"
#include "secure/observability/metrics_registry.hpp"
#include "secure/runtime/worker_pool.hpp"

#include <chrono>
#include <exception>
#include <memory>
#include <string>
#include <utility>

#include <boost/asio/bind_executor.hpp>
#include <boost/asio/dispatch.hpp>
#include <boost/asio/error.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/ssl/error.hpp>
#include <boost/asio/ssl/stream_base.hpp>
#include <boost/beast/core/error.hpp>
#include <boost/beast/http.hpp>

namespace secure {

namespace beast = boost::beast;
namespace http = beast::http;
namespace ssl = boost::asio::ssl;

using boost::asio::ip::tcp;

TlsHttpSession::TlsHttpSession(
    tcp::socket socket,
    ssl::context& tls_context,
    ConnectionManager& connection_manager,
    Logger& logger,
    Router& router,
    MiddlewarePipeline& middleware_pipeline,
    WorkerPool& worker_pool,
    MetricsRegistry& metrics_registry,
    const HttpLimits& limits
)
    : stream_(
          std::move(socket),
          tls_context
      ),
      strand_(
          boost::asio::make_strand(
              stream_.get_executor()
          )
      ),
      connection_manager_(connection_manager),
      logger_(logger),
      router_(router),
      middleware_pipeline_(
          middleware_pipeline
      ),
      worker_pool_(worker_pool),
      metrics_registry_(metrics_registry),
      limits_(limits) {
    boost::system::error_code error;

    const auto endpoint =
        stream_.next_layer()
            .socket()
            .remote_endpoint(error);

    if (error) {
        client_ip_ = "unknown";
    } else {
        client_ip_ =
            endpoint.address().to_string();
    }

    metrics_registry_.connection_opened();
}

void TlsHttpSession::start() {
    auto self = shared_from_this();

    boost::asio::dispatch(
        strand_,
        [self] {
            self->do_start();
        }
    );
}

void TlsHttpSession::stop() {
    auto self = shared_from_this();

    boost::asio::dispatch(
        strand_,
        [self] {
            self->do_stop();
        }
    );
}

void TlsHttpSession::do_start() {
    if (
        started_ ||
        stopped_
    ) {
        return;
    }

    started_ = true;

    logger_.info(
        "TLS session started from ",
        client_ip_,
        ". Waiting for handshake."
    );

    do_handshake();
}

void TlsHttpSession::do_handshake() {
    if (stopped_) {
        return;
    }

    stream_.next_layer().expires_after(
        limits_.tls_handshake_timeout
    );

    auto self = shared_from_this();

    stream_.async_handshake(
        ssl::stream_base::server,
        boost::asio::bind_executor(
            strand_,
            [self](
                const boost::system::error_code& error
            ) {
                self->handle_handshake(error);
            }
        )
    );
}

void TlsHttpSession::handle_handshake(
    const boost::system::error_code& error
) {
    if (stopped_) {
        return;
    }

    if (error) {
        if (error == beast::error::timeout) {
            logger_.warning(
                "TLS handshake timeout from ",
                client_ip_,
                '.'
            );
        } else {
            logger_.warning(
                "TLS handshake failed from ",
                client_ip_,
                ": ",
                error.message()
            );
        }

        handle_disconnect({});

        return;
    }

    logger_.info(
        "TLS handshake completed from ",
        client_ip_,
        '.'
    );

    do_read();
}

void TlsHttpSession::do_stop() {
    if (stopped_) {
        return;
    }

    stopped_ = true;

    metrics_registry_.connection_closed();

    boost::system::error_code ignored_error;

    stream_.next_layer().socket().cancel(
        ignored_error
    );

    stream_.next_layer().socket().shutdown(
        tcp::socket::shutdown_both,
        ignored_error
    );

    stream_.next_layer().socket().close(
        ignored_error
    );
}

void TlsHttpSession::do_read() {
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

    stream_.next_layer().expires_after(
        timeout
    );

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

void TlsHttpSession::handle_read(
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
            "HTTPS read timeout from ",
            client_ip_,
            '.'
        );

        handle_disconnect({});

        return;
    }

    handle_disconnect(error);
}

void TlsHttpSession::handle_request() {
    auto request =
        std::make_shared<HttpRequest>(
            std::move(request_)
        );

    const std::string client_ip =
        client_ip_;

    auto self =
        shared_from_this();

    const WorkerPool::SubmitResult result =
        worker_pool_.try_submit(
            [
                self,
                request = std::move(request),
                client_ip
            ] {
                HttpResponse response;

                try {
                    const RequestContext context{
                        *request,
                        client_ip
                    };

                    response =
                        self->middleware_pipeline_
                            .execute(
                                context,
                                [
                                    self,
                                    request
                                ] {
                                    return self->router_
                                        .dispatch(
                                            *request
                                        );
                                }
                            );
                } catch (
                    const std::exception& error
                ) {
                    self->logger_.error(
                        "Unhandled HTTPS worker "
                        "request exception: ",
                        error.what()
                    );

                    response =
                        make_json_error(
                            http::status::
                                internal_server_error,
                            "internal_server_error"
                        );

                    response.version(
                        request->version()
                    );

                    response.set(
                        http::field::server,
                        "SecureCore"
                    );

                    response.keep_alive(false);

                    response.prepare_payload();
                } catch (...) {
                    self->logger_.error(
                        "Unknown HTTPS worker "
                        "request exception."
                    );

                    response =
                        make_json_error(
                            http::status::
                                internal_server_error,
                            "internal_server_error"
                        );

                    response.version(
                        request->version()
                    );

                    response.set(
                        http::field::server,
                        "SecureCore"
                    );

                    response.keep_alive(false);

                    response.prepare_payload();
                }

                boost::asio::post(
                    self->strand_,
                    [
                        self,
                        response =
                            std::move(response)
                    ]() mutable {
                        self->complete_request(
                            std::move(response)
                        );
                    }
                );
            }
        );

    if (
        result ==
        WorkerPool::SubmitResult::accepted
    ) {
        return;
    }

    logger_.warning(
        result ==
            WorkerPool::SubmitResult::queue_full
            ? "Worker queue is full. "
              "Rejecting HTTPS request."
            : "Worker pool is stopping. "
              "Rejecting HTTPS request."
    );

    HttpResponse response =
        make_json_error(
            http::status::service_unavailable,
            result ==
                WorkerPool::SubmitResult::queue_full
                ? "server_busy"
                : "server_shutting_down"
        );

    response.version(
        request->version()
    );

    response.set(
        http::field::server,
        "SecureCore"
    );

    response.set(
        http::field::retry_after,
        "1"
    );

    response.set(
        http::field::cache_control,
        "no-store"
    );

    response.set(
        "X-Content-Type-Options",
        "nosniff"
    );

    response.keep_alive(false);

    response.prepare_payload();

    metrics_registry_.record_http_response(
        response.result_int(),
        std::chrono::microseconds{0}
    );

    send_response(
        std::move(response)
    );
}

void TlsHttpSession::complete_request(
    HttpResponse response
) {
    if (stopped_) {
        return;
    }

    send_response(
        std::move(response)
    );
}

void TlsHttpSession::send_response(
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

    stream_.next_layer().expires_after(
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
                            "HTTPS write timeout."
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
                    self->do_tls_shutdown();

                    return;
                }

                self->do_read();
            }
        )
    );
}

void TlsHttpSession::do_tls_shutdown() {
    if (stopped_) {
        return;
    }

    stream_.next_layer().expires_after(
        limits_.write_timeout
    );

    auto self = shared_from_this();

    stream_.async_shutdown(
        boost::asio::bind_executor(
            strand_,
            [self](
                const boost::system::error_code& error
            ) {
                self->handle_tls_shutdown(error);
            }
        )
    );
}

void TlsHttpSession::handle_tls_shutdown(
    const boost::system::error_code& error
) {
    if (stopped_) {
        return;
    }

    if (
        error &&
        error != boost::asio::error::eof &&
        error !=
            boost::asio::error::operation_aborted &&
        error != ssl::error::stream_truncated &&
        error != beast::error::timeout
    ) {
        logger_.warning(
            "TLS shutdown failed for ",
            client_ip_,
            ": ",
            error.message()
        );
    }

    handle_disconnect({});
}

void TlsHttpSession::send_protocol_error(
    http::status status,
    std::string_view error_code
) {
    logger_.warning(
        "Rejected HTTPS request from ",
        client_ip_,
        ": ",
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

    metrics_registry_.record_http_response(
        response.result_int(),
        std::chrono::microseconds{0}
    );

    send_response(
        std::move(response)
    );
}

void TlsHttpSession::handle_disconnect(
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
        error != beast::error::timeout &&
        error != ssl::error::stream_truncated
    ) {
        logger_.warning(
            "HTTPS connection from ",
            client_ip_,
            " ended with error: ",
            error.message()
        );
    }

    do_stop();

    connection_manager_.remove(
        shared_from_this()
    );

    logger_.info(
        "HTTPS client ",
        client_ip_,
        " disconnected. Active connections: ",
        connection_manager_.size()
    );
}

}  // namespace secure
