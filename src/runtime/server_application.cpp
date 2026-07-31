#include "secure/runtime/server_application.hpp"
#include <utility>
#include <csignal>
#include <iostream>

namespace secure {
ServerApplication::ServerApplication(
    ServerConfig config
)
    : config_(std::move(config)),
      signals_(io_context_, SIGINT, SIGTERM),
      tcp_server_(
          io_context_,
          config_.listen_address(),
          config_.listen_port()
      ) {
    signals_.async_wait(
        [this](
            const boost::system::error_code& error,
            int signal_number
        ) {
            if (error) {
                return;
            }

            std::cout
                << "\nReceived signal "
                << signal_number
                << ", stopping server...\n";

            stop();
        }
    );
}
int ServerApplication::run() {
    std::cout << "SecureCore server starting...\n";

    tcp_server_.start();

    io_context_.run();

    std::cout << "SecureCore server stopped.\n";
    return 0;
}

void ServerApplication::stop() {
    tcp_server_.stop();
    io_context_.stop();
}

}  // namespace secure