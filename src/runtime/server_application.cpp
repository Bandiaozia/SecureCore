#include "secure/runtime/server_application.hpp"

#include "secure/http/admin_routes.hpp"
#include "secure/http/account_routes.hpp"
#include "secure/http/http_limits.hpp"
#include "secure/http/metrics_routes.hpp"
#include "secure/http/routes.hpp"

#include <array>
#include <chrono>
#include <csignal>
#include <exception>
#include <filesystem>
#include <memory>
#include <stdexcept>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include <boost/asio/ssl/context.hpp>
#include <openssl/err.h>
#include <openssl/ssl.h>

namespace secure {

namespace {

namespace ssl = boost::asio::ssl;

std::string last_openssl_error() {
    const unsigned long error_code =
        ERR_get_error();

    if (error_code == 0) {
        return "unknown OpenSSL error";
    }

    std::array<char, 256> buffer{};

    ERR_error_string_n(
        error_code,
        buffer.data(),
        buffer.size()
    );

    return std::string(buffer.data());
}

void require_regular_file(
    const std::string& path,
    const char* description
) {
    std::error_code error;

    const bool regular_file =
        std::filesystem::is_regular_file(
            path,
            error
        );

    if (
        error ||
        !regular_file
    ) {
        throw std::runtime_error(
            std::string(description) +
            " does not exist or is not a "
            "regular file: " +
            path
        );
    }
}

std::unique_ptr<ssl::context>
make_tls_context(
    const ServerConfig& config
) {
    if (!config.tls_enabled()) {
        return nullptr;
    }

    if (
        config.tls_certificate_file().empty()
    ) {
        throw std::runtime_error(
            "tls_certificate_file is required "
            "when tls_enabled=true"
        );
    }

    if (
        config.tls_private_key_file().empty()
    ) {
        throw std::runtime_error(
            "tls_private_key_file is required "
            "when tls_enabled=true"
        );
    }

    require_regular_file(
        config.tls_certificate_file(),
        "TLS certificate file"
    );

    require_regular_file(
        config.tls_private_key_file(),
        "TLS private key file"
    );

    auto context =
        std::make_unique<ssl::context>(
            ssl::context::tls_server
        );

    context->set_options(
        ssl::context::default_workarounds |
        ssl::context::no_sslv2 |
        ssl::context::no_sslv3 |
        ssl::context::no_tlsv1 |
        ssl::context::no_tlsv1_1 |
        ssl::context::no_compression
    );

    SSL_CTX* native_context =
        context->native_handle();

    if (
        SSL_CTX_set_min_proto_version(
            native_context,
            TLS1_2_VERSION
        ) != 1
    ) {
        throw std::runtime_error(
            "Failed to set minimum TLS "
            "version: " +
            last_openssl_error()
        );
    }

#ifdef SSL_OP_NO_RENEGOTIATION
    SSL_CTX_set_options(
        native_context,
        SSL_OP_NO_RENEGOTIATION
    );
#endif

#ifdef SSL_MODE_RELEASE_BUFFERS
    SSL_CTX_set_mode(
        native_context,
        SSL_MODE_RELEASE_BUFFERS
    );
#endif

    boost::system::error_code error;

    context->use_certificate_chain_file(
        config.tls_certificate_file(),
        error
    );

    if (error) {
        throw std::runtime_error(
            "Failed to load TLS certificate "
            "chain '" +
            config.tls_certificate_file() +
            "': " +
            error.message()
        );
    }

    error.clear();

    context->use_private_key_file(
        config.tls_private_key_file(),
        ssl::context::pem,
        error
    );

    if (error) {
        throw std::runtime_error(
            "Failed to load TLS private key: " +
            error.message()
        );
    }

    if (
        SSL_CTX_check_private_key(
            native_context
        ) != 1
    ) {
        throw std::runtime_error(
            "TLS private key does not match "
            "the certificate: " +
            last_openssl_error()
        );
    }

    return context;
}

}  // namespace

ServerApplication::ServerApplication(
    ServerConfig config
)
    : config_(std::move(config)),
      logger_(config_.log_file()),
      rate_limiter_(
          config_
              .http_rate_limit_requests(),
          std::chrono::seconds{
              config_
                  .http_rate_limit_window_seconds()
          }
      ),
      database_(
          config_.database_path(),
          config_.database_pool_size(),
          std::chrono::milliseconds{
              config_
                  .database_acquire_timeout_ms()
          }
      ),
      migration_runner_(database_),
      user_repository_(database_),
      auth_session_repository_(database_),
      password_hasher_(),
      token_service_(),
      user_service_(
          user_repository_,
          password_hasher_
      ),
      auth_service_(
          database_,
          user_repository_,
          auth_session_repository_,
          password_hasher_,
          token_service_
      ),
      admin_service_(
          database_,
          auth_service_,
          user_repository_,
          auth_session_repository_
      ),
      account_security_service_(
          database_,
          auth_service_,
          user_repository_,
          auth_session_repository_,
          password_hasher_,
          token_service_
      ),
      io_work_guard_(
          boost::asio::make_work_guard(
              io_context_
          )
      ),
      tls_context_(
          make_tls_context(config_)
      ),
      worker_pool_(
          config_.worker_threads(),
          config_.worker_queue_capacity()
      ),
      signals_(
          io_context_,
          SIGINT,
          SIGTERM
      ),
      http_server_(
          io_context_,
          config_.listen_address(),
          config_.listen_port(),
          tls_context_.get(),
          logger_,
          router_,
          middleware_pipeline_,
          worker_pool_,
          metrics_registry_,
          HttpLimits{
              config_
                  .http_max_header_bytes(),

              config_
                  .http_max_body_bytes(),

              std::chrono::seconds{
                  config_
                      .http_read_timeout_seconds()
              },

              std::chrono::seconds{
                  config_
                      .http_write_timeout_seconds()
              },

              std::chrono::seconds{
                  config_
                      .http_idle_timeout_seconds()
              },

              config_
                  .http_max_connections(),

              std::chrono::seconds{
                  config_
                      .tls_handshake_timeout_seconds()
              }
          }
      ) {
    migration_runner_.apply();

    logger_.info(
        "Database initialized."
    );

    register_routes(
        router_,
        database_,
        service_state_,
        user_service_,
        auth_service_
    );

    register_admin_routes(
        router_,
        admin_service_
    );

    register_account_routes(
        router_,
        account_security_service_
    );

    register_metrics_routes(
        router_,
        metrics_registry_,
        worker_pool_,
        database_,
        service_state_
    );

    register_default_middlewares(
        middleware_pipeline_,
        rate_limiter_,
        logger_,
        metrics_registry_
    );

    signals_.async_wait(
        [this](
            const boost::system::error_code& error,
            int signal_number
        ) {
            if (error) {
                return;
            }

            logger_.info(
                "Received signal ",
                signal_number,
                ", beginning graceful shutdown."
            );

            stop();
        }
    );
}

int ServerApplication::run() {
    logger_.info(
        "SecureCore server starting."
    );

    logger_.info(
        "Configuration: ",
        config_.redacted_summary(),
        '.'
    );

    logger_.info(
        "Starting I/O thread pool with ",
        config_.io_threads(),
        " threads."
    );

    logger_.info(
        "Worker pool: ",
        config_.worker_threads(),
        " threads, queue capacity ",
        config_.worker_queue_capacity(),
        '.'
    );

    if (config_.tls_enabled()) {
        logger_.info(
            "TLS enabled. Minimum protocol "
            "version: TLS 1.2."
        );
    } else {
        logger_.warning(
            "TLS is disabled. Authentication "
            "traffic is not encrypted."
        );
    }

    logger_.info(
        "HTTP rate limit: ",
        config_
            .http_rate_limit_requests(),
        " requests per ",
        config_
            .http_rate_limit_window_seconds(),
        " second(s)."
    );

    logger_.info(
        "Database pool: ",
        database_.pool_size(),
        " connections, acquire timeout ",
        database_.acquire_timeout().count(),
        " ms."
    );

    logger_.info(
        "Database health check: ",
        database_.healthy()
            ? "ready"
            : "unavailable",
        '.'
    );

    logger_.info(
        "Graceful shutdown period: ",
        config_.shutdown_grace_period_ms(),
        " ms."
    );

    service_state_.mark_running();
    http_server_.start();

    std::vector<std::thread> workers;

    workers.reserve(
        config_.io_threads() - 1
    );

    for (
        std::uint32_t index = 1;
        index < config_.io_threads();
        ++index
    ) {
        workers.emplace_back(
            [this] {
                run_io_context();
            }
        );
    }

    run_io_context();

    for (auto& worker : workers) {
        if (worker.joinable()) {
            worker.join();
        }
    }

    join_shutdown_thread();

    logger_.info(
        "SecureCore server stopped."
    );

    return 0;
}

void ServerApplication::run_io_context() {
    try {
        io_context_.run();
    } catch (
        const std::exception& error
    ) {
        logger_.error(
            "Unhandled I/O thread exception: ",
            error.what()
        );

        stop();
    } catch (...) {
        logger_.error(
            "Unknown I/O thread exception."
        );

        stop();
    }
}

void ServerApplication::stop() {
    bool expected = false;

    if (
        !stopping_.compare_exchange_strong(
            expected,
            true
        )
    ) {
        return;
    }

    static_cast<void>(
        service_state_.begin_draining()
    );

    logger_.info(
        "Server entered draining state. "
        "Grace period: ",
        config_.shutdown_grace_period_ms(),
        " ms."
    );

    http_server_.begin_draining();

    std::scoped_lock lock(
        shutdown_thread_mutex_
    );

    shutdown_thread_ = std::thread(
        [this] {
            run_shutdown_sequence();
        }
    );
}

void ServerApplication::run_shutdown_sequence() {
    const auto grace_period =
        std::chrono::milliseconds{
            config_.shutdown_grace_period_ms()
        };

    const bool drained =
        http_server_.wait_until_idle(
            grace_period
        );

    if (drained) {
        logger_.info(
            "All HTTP connections drained "
            "within the grace period."
        );
    } else {
        logger_.warning(
            "Graceful shutdown period expired "
            "with ",
            http_server_.active_connections(),
            " active connection(s). Forcing "
            "connection shutdown."
        );

        const bool force_stop_completed =
            http_server_.force_stop_and_wait(
                std::chrono::seconds{2}
            );

        if (!force_stop_completed) {
            logger_.error(
                "Timed out waiting for forced "
                "HTTP connection shutdown."
            );
        }
    }

    worker_pool_.stop();
    service_state_.mark_stopped();

    boost::system::error_code ignored_error;
    signals_.cancel(ignored_error);

    /*
     * Worker tasks can temporarily be the only remaining work in the
     * process.  Their completion handlers are posted back to io_context_.
     * Keep the executor alive until WorkerPool has fully drained and joined,
     * then release the guard and stop the event loop.
     */
    io_work_guard_.reset();
    io_context_.stop();
}

void ServerApplication::join_shutdown_thread() {
    std::thread shutdown_thread;

    {
        std::scoped_lock lock(
            shutdown_thread_mutex_
        );

        if (shutdown_thread_.joinable()) {
            shutdown_thread = std::move(
                shutdown_thread_
            );
        }
    }

    if (shutdown_thread.joinable()) {
        shutdown_thread.join();
    }
}

}  // namespace secure
