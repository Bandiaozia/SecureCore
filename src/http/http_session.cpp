#include "secure/http/http_session.hpp"

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
#include <boost/beast/core/error.hpp>
#include <boost/beast/http.hpp>

namespace secure {

namespace beast = boost::beast;
namespace http = beast::http;

using boost::asio::ip::tcp;

namespace {

bool allowed_during_drain(
    const HttpRequest& request
) {
    const auto target = request.target();
    const auto query = target.find('?');
    const auto path = target.substr(0, query);

    return (
        path == "/ready" ||
        path == "/metrics"
    );
}

}  // namespace

HttpSession::HttpSession(
    tcp::socket socket,
    ConnectionManager& connection_manager,
    Logger& logger,
    Router& router,
    MiddlewarePipeline& middleware_pipeline,
    WorkerPool& worker_pool,
    MetricsRegistry& metrics_registry,
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
      middleware_pipeline_(
          middleware_pipeline
      ),
      worker_pool_(worker_pool),
      metrics_registry_(metrics_registry),
      limits_(limits) {
    boost::system::error_code error;

    const auto endpoint =
        stream_.socket().remote_endpoint(
            error
        );

    if (error) {
        client_ip_ = "unknown";
    } else {
        client_ip_ =
            endpoint.address().to_string();
    }

    metrics_registry_.connection_opened();
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

void HttpSession::drain() {
    auto self = shared_from_this();

    boost::asio::dispatch(
        strand_,
        [self] {
            self->do_drain();
        }
    );
}

void HttpSession::stop() {
    auto self = shared_from_this();

    boost::asio::dispatch(
        strand_,
        [self] {
            self->handle_disconnect({});
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
        "HTTP session started from ",
        client_ip_,
        '.'
    );

    do_read();
}

void HttpSession::do_drain() {
    if (draining_ || stopped_) {
        return;
    }

    draining_ = true;

    if (phase_ == Phase::created) {
        handle_disconnect({});
    }
}

void HttpSession::do_stop() {
    if (stopped_) {
        return;
    }

    stopped_ = true;
    phase_ = Phase::stopped;

    finish_request();
    metrics_registry_.connection_closed();

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

    phase_ = Phase::reading;
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
        phase_ = Phase::processing;
        request_active_ = true;
        metrics_registry_.request_started();

        if (
            draining_ &&
            !allowed_during_drain(request_)
        ) {
            reject_new_request_during_drain();
            return;
        }

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
            "HTTP read timeout from ",
            client_ip_,
            '.'
        );

        handle_disconnect({});

        return;
    }

    handle_disconnect(error);
}

void HttpSession::handle_request() {
    /*
     * 当前请求在收到响应前不会启动下一次读取，
     * 因此可以把 request_ 移交给后台任务。
     */
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
                        "Unhandled worker request "
                        "exception: ",
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
                        "Unknown worker request "
                        "exception."
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
              "Rejecting HTTP request."
            : "Worker pool is stopping. "
              "Rejecting HTTP request."
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

void HttpSession::complete_request(
    HttpResponse response
) {
    if (stopped_) {
        return;
    }

    if (draining_) {
        response.keep_alive(false);
    }

    send_response(
        std::move(response)
    );
}

void HttpSession::reject_new_request_during_drain() {
    HttpResponse response =
        make_json_error(
            http::status::service_unavailable,
            "server_shutting_down"
        );

    response.version(request_.version());
    response.set(http::field::server, "SecureCore");
    response.set(http::field::retry_after, "1");
    response.set(http::field::cache_control, "no-store");
    response.keep_alive(false);
    response.prepare_payload();

    metrics_registry_.record_http_response(
        response.result_int(),
        std::chrono::microseconds{0}
    );

    send_response(std::move(response));
}

void HttpSession::finish_request() noexcept {
    if (!request_active_) {
        return;
    }

    request_active_ = false;
    metrics_registry_.request_finished();
}

void HttpSession::send_response(
    HttpResponse response
) {
    if (stopped_) {
        return;
    }

    if (draining_) {
        response.keep_alive(false);
    }

    const bool should_close =
        response.need_eof();

    phase_ = Phase::writing;

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

                self->finish_request();

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

                /*
                 * 如果 draining 在本次响应开始写出之后才发生，
                 * 该响应没有携带 Connection: close。此时不能在
                 * 写完成回调里直接关闭，否则客户端已经发送的
                 * /ready 或 /metrics 请求会留在套接字中直到超时。
                 *
                 * 继续启动一次读取。下一个请求会看到 draining_：
                 * - /ready、/metrics 可以完成，并以 Connection: close 返回；
                 * - 其他请求返回 503，并关闭连接。
                 *
                 * 如果响应是在 draining 状态下开始发送的，
                 * send_response() 已把 keep_alive 设为 false，
                 * 因而 should_close 本身就是 true。
                 */
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
        "Rejected HTTP request from ",
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
            "HTTP connection from ",
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
        "HTTP client ",
        client_ip_,
        " disconnected. Active connections: ",
        connection_manager_.size()
    );
}

}  // namespace secure
