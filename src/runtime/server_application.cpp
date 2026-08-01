#include "secure/runtime/server_application.hpp"

#include "secure/http/admin_routes.hpp"
#include "secure/http/account_routes.hpp"
#include "secure/http/http_limits.hpp"
#include "secure/http/routes.hpp"

#include <chrono>
#include <csignal>
#include <exception>
#include <thread>
#include <utility>
#include <vector>

namespace secure {

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
          config_.database_path()
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
          user_repository_,
          auth_session_repository_,
          password_hasher_,
          token_service_
      ),
      admin_service_(
          auth_service_,
          user_repository_,
          auth_session_repository_
      ),
      account_security_service_(
          auth_service_,
          user_repository_,
          auth_session_repository_,
          password_hasher_,
          token_service_
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
          logger_,
          router_,
          middleware_pipeline_,
          worker_pool_,
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
                  .http_max_connections()
          }
      ) {
    migration_runner_.apply();

    logger_.info(
        "Database initialized at ",
        database_.path().string(),
        '.'
    );

    register_routes(
        router_,
        database_,
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

    register_default_middlewares(
        middleware_pipeline_,
        rate_limiter_,
        logger_
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
                ", stopping server."
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
        "Database path: ",
        config_.database_path(),
        '.'
    );

    logger_.info(
        "Database health check: ",
        database_.healthy()
            ? "ready"
            : "unavailable",
        '.'
    );

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

    /*
     * 先停止接收连接，再停止接收新的后台任务。
     * WorkerPool 会处理完已经进入队列的任务后退出。
     */
    http_server_.stop();

    worker_pool_.stop();
}

}  // namespace secure
