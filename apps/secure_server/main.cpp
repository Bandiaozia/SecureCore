#include "secure/config/server_config.hpp"
#include "secure/runtime/server_application.hpp"

#include <cstdlib>
#include <exception>
#include <iostream>
#include <string>
#include <utility>

int main(int argc, char* argv[]) {
    try {
        const std::string config_path =
            argc >= 2
                ? argv[1]
                : "configs/server.conf";

        auto config =
            secure::ServerConfig::load_from_file(
                config_path
            );

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