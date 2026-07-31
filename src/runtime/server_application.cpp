#include "secure/runtime/server_application.hpp"

#include <csignal>
#include <utility>

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
      tcp_server_(
          io_context_,
          config_.listen_address(),
          config_.listen_port(),
          logger_
      ) {
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

    tcp_server_.start();

    io_context_.run();

    logger_.info(
        "SecureCore server stopped."
    );

    return 0;
}

void ServerApplication::stop() {
    tcp_server_.stop();
    io_context_.stop();
}

}  // namespace secure
