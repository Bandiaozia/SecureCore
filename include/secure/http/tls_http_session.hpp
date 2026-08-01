#pragma once

#include "secure/http/http_limits.hpp"
#include "secure/http/http_types.hpp"
#include "secure/net/connection.hpp"

#include <cstddef>
#include <memory>
#include <optional>
#include <string>
#include <string_view>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ssl/context.hpp>
#include <boost/asio/ssl/stream.hpp>
#include <boost/asio/strand.hpp>
#include <boost/beast/core/flat_buffer.hpp>
#include <boost/beast/core/tcp_stream.hpp>
#include <boost/beast/http/parser.hpp>
#include <boost/system/error_code.hpp>

namespace secure {

class ConnectionManager;
class Logger;
class MetricsRegistry;
class MiddlewarePipeline;
class Router;
class WorkerPool;

class TlsHttpSession final
    : public Connection,
      public std::enable_shared_from_this<
          TlsHttpSession
      > {
public:
    TlsHttpSession(
        boost::asio::ip::tcp::socket socket,
        boost::asio::ssl::context& tls_context,
        ConnectionManager& connection_manager,
        Logger& logger,
        Router& router,
        MiddlewarePipeline& middleware_pipeline,
        WorkerPool& worker_pool,
        MetricsRegistry& metrics_registry,
        const HttpLimits& limits
    );

    void start() override;

    void drain() override;

    void stop() override;

private:
    using RequestParser =
        boost::beast::http::request_parser<
            boost::beast::http::string_body
        >;

    using TlsStream =
        boost::asio::ssl::stream<
            boost::beast::tcp_stream
        >;

    enum class Phase {
        created,
        handshaking,
        reading,
        processing,
        writing,
        shutting_down,
        stopped
    };

    void do_start();

    void do_drain();

    void do_handshake();

    void handle_handshake(
        const boost::system::error_code& error
    );

    void do_stop();

    void do_read();

    void handle_read(
        const boost::system::error_code& error
    );

    void handle_request();

    void complete_request(
        HttpResponse response
    );

    void reject_new_request_during_drain();

    void finish_request() noexcept;

    void send_response(
        HttpResponse response
    );

    void do_tls_shutdown();

    void handle_tls_shutdown(
        const boost::system::error_code& error
    );

    void send_protocol_error(
        boost::beast::http::status status,
        std::string_view error_code
    );

    void handle_disconnect(
        const boost::system::error_code& error
    );

    TlsStream stream_;

    boost::asio::strand<
        boost::asio::any_io_executor
    > strand_;

    ConnectionManager& connection_manager_;

    Logger& logger_;

    Router& router_;

    MiddlewarePipeline& middleware_pipeline_;

    WorkerPool& worker_pool_;

    MetricsRegistry& metrics_registry_;

    HttpLimits limits_;

    std::string client_ip_;

    boost::beast::flat_buffer buffer_;

    std::optional<RequestParser> parser_;

    HttpRequest request_;

    std::size_t completed_requests_{0};

    Phase phase_{Phase::created};

    bool request_active_{false};

    bool draining_{false};

    bool stopped_{false};

    bool started_{false};
};

}  // namespace secure
