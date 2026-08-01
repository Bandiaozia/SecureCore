#include "secure/config/server_config.hpp"
#include "secure/runtime/server_application.hpp"
#include "secure/version.hpp"

#include <cstdlib>
#include <exception>
#include <iostream>
#include <string>
#include <string_view>
#include <utility>

int main(int argc, char* argv[]) {
    if (argc == 2 && std::string_view{argv[1]} == "--version") {
        std::cout
            << "secure-server "
            << secure::build::version
            << " ("
            << secure::build::git_commit
            << ")\n";

        return EXIT_SUCCESS;
    }

    try {
        const std::string config_path =
            argc >= 2
                ? argv[1]
                : "configs/server.conf";

        auto config =
            secure::ServerConfig::load_from_file(
                config_path
            );

        config.validate_for_server();

        secure::ServerApplication application(
            std::move(config)
        );

        return application.run();
    } catch (const std::exception& error) {
        std::cerr
            << "SecureCore startup failed: "
            << error.what()
            << '\n';

        return EXIT_FAILURE;
    }
}