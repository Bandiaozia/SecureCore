#include "secure/config/server_config.hpp"

#include <array>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

namespace {

constexpr std::array environment_variables{
    "SECURECORE_ENVIRONMENT",
    "SECURECORE_LISTEN_ADDRESS",
    "SECURECORE_LISTEN_PORT",
    "SECURECORE_LOG_FILE",
    "SECURECORE_DATABASE_PATH",
    "SECURECORE_IO_THREADS",
    "SECURECORE_WORKER_THREADS",
    "SECURECORE_WORKER_QUEUE_CAPACITY",
    "SECURECORE_TLS_ENABLED",
    "SECURECORE_TLS_CERTIFICATE_FILE",
    "SECURECORE_TLS_PRIVATE_KEY_FILE",
    "SECURECORE_TLS_HANDSHAKE_TIMEOUT_SECONDS",
    "SECURECORE_HTTP_MAX_CONNECTIONS",
    "SECURECORE_HTTP_RATE_LIMIT_REQUESTS",
    "SECURECORE_HTTP_RATE_LIMIT_WINDOW_SECONDS",
    "SECURECORE_HTTP_MAX_HEADER_BYTES",
    "SECURECORE_HTTP_MAX_BODY_BYTES",
    "SECURECORE_HTTP_READ_TIMEOUT_SECONDS",
    "SECURECORE_HTTP_WRITE_TIMEOUT_SECONDS",
    "SECURECORE_HTTP_IDLE_TIMEOUT_SECONDS"
};

class EnvironmentGuard final {
public:
    EnvironmentGuard() {
        for (const char* name : environment_variables) {
            const char* value = std::getenv(name);

            if (value != nullptr) {
                saved_.push_back({name, value});
            }

            ::unsetenv(name);
        }
    }

    ~EnvironmentGuard() {
        for (const char* name : environment_variables) {
            ::unsetenv(name);
        }

        for (const auto& item : saved_) {
            ::setenv(
                item.name.c_str(),
                item.value.c_str(),
                1
            );
        }
    }

private:
    struct SavedVariable final {
        std::string name;
        std::string value;
    };

    std::vector<SavedVariable> saved_;
};

void require(
    bool condition,
    std::string_view message
) {
    if (!condition) {
        throw std::runtime_error(
            std::string(message)
        );
    }
}

template <typename Function>
void require_throws(
    Function&& function,
    std::string_view expected_text
) {
    try {
        function();
    } catch (const std::exception& error) {
        require(
            std::string(error.what()).find(
                expected_text
            ) != std::string::npos,
            "Exception did not contain expected text"
        );

        return;
    }

    throw std::runtime_error(
        "Expected an exception"
    );
}

void write_file(
    const std::filesystem::path& path,
    const std::string& content
) {
    std::ofstream output(path);

    if (!output.is_open()) {
        throw std::runtime_error(
            "Failed to create test file"
        );
    }

    output << content;
}

std::string base_config(
    const std::filesystem::path& root
) {
    return
        "environment=development\n"
        "listen_address=127.0.0.1\n"
        "listen_port=9091\n"
        "log_file=" +
        (root / "logs/server.log").string() +
        "\n"
        "database_path=" +
        (root / "data/server.db").string() +
        "\n"
        "io_threads=2\n"
        "worker_threads=3\n"
        "worker_queue_capacity=32\n"
        "tls_enabled=false\n"
        "http_max_connections=64\n"
        "http_rate_limit_requests=10\n"
        "http_rate_limit_window_seconds=2\n";
}

}  // namespace

int main() {
    EnvironmentGuard environment_guard;

    const auto root =
        std::filesystem::temp_directory_path() /
        (
            "securecore-config-test-" +
            std::to_string(::getpid())
        );

    std::filesystem::remove_all(root);
    std::filesystem::create_directories(root);

    try {
        const auto config_path =
            root / "server.conf";

        write_file(
            config_path,
            base_config(root)
        );

        auto config =
            secure::ServerConfig::load_from_file(
                config_path.string()
            );

        require(
            config.environment() == "development",
            "File environment was not loaded"
        );

        require(
            config.listen_port() == 9091,
            "File port was not loaded"
        );

        require(
            config.worker_threads() == 3,
            "File worker thread count was not loaded"
        );

        config.validate_for_server();

        require(
            std::filesystem::is_directory(
                root / "logs"
            ),
            "Log directory was not created"
        );

        require(
            std::filesystem::is_directory(
                root / "data"
            ),
            "Database directory was not created"
        );

        ::setenv(
            "SECURECORE_LISTEN_PORT",
            "9443",
            1
        );

        ::setenv(
            "SECURECORE_WORKER_THREADS",
            "7",
            1
        );

        ::setenv(
            "SECURECORE_ENVIRONMENT",
            "test",
            1
        );

        config =
            secure::ServerConfig::load_from_file(
                config_path.string()
            );

        require(
            config.listen_port() == 9443,
            "Environment did not override port"
        );

        require(
            config.worker_threads() == 7,
            "Environment did not override workers"
        );

        require(
            config.environment() == "test",
            "Environment mode was not overridden"
        );

        ::setenv(
            "SECURECORE_LISTEN_PORT",
            "not-a-port",
            1
        );

        require_throws(
            [&] {
                static_cast<void>(
                    secure::ServerConfig::
                        load_from_file(
                            config_path.string()
                        )
                );
            },
            "SECURECORE_LISTEN_PORT"
        );

        ::unsetenv("SECURECORE_LISTEN_PORT");
        ::unsetenv("SECURECORE_WORKER_THREADS");
        ::unsetenv("SECURECORE_ENVIRONMENT");

        write_file(
            config_path,
            base_config(root) +
            "environment=production\n"
            "listen_address=0.0.0.0\n"
        );

        config =
            secure::ServerConfig::load_from_file(
                config_path.string()
            );

        require_throws(
            [&] {
                config.validate_for_server();
            },
            "unencrypted HTTP"
        );

        const auto certificate_path =
            root / "certificate.pem";

        const auto private_key_path =
            root / "private-key.pem";

        write_file(certificate_path, "certificate");
        write_file(private_key_path, "private-key");

        ::chmod(
            private_key_path.c_str(),
            0644
        );

        write_file(
            config_path,
            base_config(root) +
            "tls_enabled=true\n"
            "tls_certificate_file=" +
            certificate_path.string() +
            "\n"
            "tls_private_key_file=" +
            private_key_path.string() +
            "\n"
        );

        config =
            secure::ServerConfig::load_from_file(
                config_path.string()
            );

        require_throws(
            [&] {
                config.validate_for_server();
            },
            "chmod 600"
        );

        ::chmod(
            private_key_path.c_str(),
            0600
        );

        config.validate_for_server();

        const std::string summary =
            config.redacted_summary();

        require(
            summary.find(private_key_path.string()) ==
                std::string::npos,
            "Summary leaked private key path"
        );

        require(
            summary.find(config.database_path()) ==
                std::string::npos,
            "Summary leaked database path"
        );

        std::filesystem::remove_all(root);

        std::cout
            << "Secure configuration tests passed.\n";

        return EXIT_SUCCESS;
    } catch (const std::exception& error) {
        std::filesystem::remove_all(root);

        std::cerr
            << "Secure configuration test failed: "
            << error.what()
            << '\n';

        return EXIT_FAILURE;
    }
}
