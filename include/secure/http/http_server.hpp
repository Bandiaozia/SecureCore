#pragma once

#include "secure/http/http_limits.hpp"
#include "secure/net/connection_manager.hpp"

#include <chrono>
#include <cstdint>
#include <string>

#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ssl/context.hpp>
#include <boost/asio/strand.hpp>

namespace secure {

class Logger;
class MetricsRegistry;
class MiddlewarePipeline;
class Router;
class WorkerPool;
class TrustedProxyResolver;

class HttpServer final {
public:
    HttpServer(
        boost::asio::io_context& io_context,
        const std::string& listen_address,
        std::uint16_t port,
        boost::asio::ssl::context* tls_context,
        Logger& logger,
        Router& router,
        MiddlewarePipeline& middleware_pipeline,
        WorkerPool& worker_pool,
        MetricsRegistry& metrics_registry,
        TrustedProxyResolver& trusted_proxy_resolver,
        HttpLimits limits
    );

    void start();

    void begin_draining();

    void stop();

    [[nodiscard]]
    bool force_stop_and_wait(
        std::chrono::milliseconds timeout
    );

    [[nodiscard]]
    bool wait_until_idle(
        std::chrono::milliseconds timeout
    ) const;

    [[nodiscard]]
    std::size_t active_connections() const;

private:
    void do_accept();

    void reject_connection(
        boost::asio::ip::tcp::socket socket
    );

    void close_acceptor();

    void do_begin_draining();

    void do_stop();

    [[nodiscard]]
    const char* protocol_name() const noexcept;

    boost::asio::ssl::context* tls_context_;

    Logger& logger_;

    Router& router_;

    MiddlewarePipeline& middleware_pipeline_;

    WorkerPool& worker_pool_;

    MetricsRegistry& metrics_registry_;

    TrustedProxyResolver& trusted_proxy_resolver_;

    HttpLimits limits_;

    ConnectionManager connection_manager_;

    boost::asio::strand<
        boost::asio::io_context::executor_type
    > strand_;

    boost::asio::ip::tcp::acceptor acceptor_;

    bool draining_{false};

    bool stopped_{false};
};

}  // namespace secure
