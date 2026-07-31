#include "secure/runtime/server_application.hpp"

#include <cstdlib>
#include <exception>
#include <iostream>

int main() {
    try {
        secure::ServerApplication application;
        return application.run();
    } catch (const std::exception& error) {
        std::cerr
            << "SecureCore startup failed: "
            << error.what()
            << '\n';

        return EXIT_FAILURE;
    }
}