#include "secure/runtime/server_application.hpp"

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
              },  config_.http_max_connections()
          }
      ) {
    register_routes(router_);

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
    } catch (const std::exception& error) {
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

    http_server_.stop();
}

}  // namespace secure
