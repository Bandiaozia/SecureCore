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
    "SECURECORE_DATABASE_POOL_SIZE",
    "SECURECORE_DATABASE_ACQUIRE_TIMEOUT_MS",
    "SECURECORE_IO_THREADS",
    "SECURECORE_WORKER_THREADS",
    "SECURECORE_WORKER_QUEUE_CAPACITY",
    "SECURECORE_SHUTDOWN_GRACE_PERIOD_MS",
    "SECURECORE_AUDIT_RETENTION_DAYS",
    "SECURECORE_METRICS_REQUIRE_AUTH",
    "SECURECORE_REGISTRATION_ENABLED",
    "SECURECORE_AUTH_LOGIN_ACCOUNT_FAILURE_LIMIT",
    "SECURECORE_AUTH_LOGIN_IP_FAILURE_LIMIT",
    "SECURECORE_AUTH_LOGIN_FAILURE_WINDOW_SECONDS",
    "SECURECORE_AUTH_LOGIN_LOCKOUT_SECONDS",
    "SECURECORE_AUTH_LOGIN_MAX_LOCKOUT_SECONDS",
    "SECURECORE_AUTH_LOGIN_MAX_TRACKED_ACCOUNTS",
    "SECURECORE_AUTH_LOGIN_MAX_TRACKED_IPS",
    "SECURECORE_TLS_ENABLED",
    "SECURECORE_TLS_CERTIFICATE_FILE",
    "SECURECORE_TLS_PRIVATE_KEY_FILE",
    "SECURECORE_TLS_HANDSHAKE_TIMEOUT_SECONDS",
    "SECURECORE_TRUSTED_PROXY_CIDRS",
    "SECURECORE_PROXY_FORWARDED_HEADER_MAX_BYTES",
    "SECURECORE_CORS_ALLOWED_ORIGINS",
    "SECURECORE_CORS_ALLOW_CREDENTIALS",
    "SECURECORE_CORS_MAX_AGE_SECONDS",
    "SECURECORE_HSTS_ENABLED",
    "SECURECORE_HSTS_MAX_AGE_SECONDS",
    "SECURECORE_HSTS_INCLUDE_SUBDOMAINS",
    "SECURECORE_HSTS_PRELOAD",
    "SECURECORE_HTTP_MAX_CONNECTIONS",
    "SECURECORE_HTTP_RATE_LIMIT_REQUESTS",
    "SECURECORE_HTTP_RATE_LIMIT_WINDOW_SECONDS",
    "SECURECORE_HTTP_RATE_LIMIT_MAX_BUCKETS",
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
        "database_pool_size=2\n"
        "database_acquire_timeout_ms=250\n"
        "io_threads=2\n"
        "worker_threads=3\n"
        "worker_queue_capacity=32\n"
        "shutdown_grace_period_ms=1500\n"
        "audit_retention_days=45\n"
        "metrics_require_auth=true\n"
        "registration_enabled=true\n"
        "auth_login_account_failure_limit=4\n"
        "auth_login_ip_failure_limit=12\n"
        "auth_login_failure_window_seconds=90\n"
        "auth_login_lockout_seconds=15\n"
        "auth_login_max_lockout_seconds=120\n"
        "auth_login_max_tracked_accounts=2000\n"
        "auth_login_max_tracked_ips=3000\n"
        "tls_enabled=false\n"
        "trusted_proxy_cidrs=127.0.0.1/32,10.0.0.0/8\n"
        "proxy_forwarded_header_max_bytes=2048\n"
        "cors_allowed_origins=https://app.example.com,https://admin.example.com\n"
        "cors_allow_credentials=true\n"
        "cors_max_age_seconds=300\n"
        "hsts_enabled=true\n"
        "hsts_max_age_seconds=31536000\n"
        "hsts_include_subdomains=true\n"
        "hsts_preload=false\n"
        "http_max_connections=64\n"
        "http_rate_limit_requests=10\n"
        "http_rate_limit_window_seconds=2\n"
        "http_rate_limit_max_buckets=4000\n";
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

        require(
            config.database_pool_size() == 2,
            "File database pool size was not loaded"
        );

        require(
            config.shutdown_grace_period_ms() == 1500,
            "File shutdown grace period was not loaded"
        );

        require(
            config.audit_retention_days() == 45,
            "File audit retention was not loaded"
        );

        require(
            config.metrics_require_auth(),
            "File metrics authentication setting was not loaded"
        );

        require(
            config.registration_enabled(),
            "File registration setting was not loaded"
        );

        require(
            config.auth_login_account_failure_limit() == 4,
            "File account failure limit was not loaded"
        );

        require(
            config.auth_login_ip_failure_limit() == 12,
            "File IP failure limit was not loaded"
        );

        require(
            config.auth_login_failure_window_seconds() == 90,
            "File login failure window was not loaded"
        );

        require(
            config.auth_login_lockout_seconds() == 15,
            "File login lockout was not loaded"
        );

        require(
            config.auth_login_max_lockout_seconds() == 120,
            "File maximum login lockout was not loaded"
        );

        require(
            config.auth_login_max_tracked_accounts() == 2000 &&
            config.auth_login_max_tracked_ips() == 3000,
            "File authentication tracking capacities were not loaded"
        );

        require(
            config.http_rate_limit_max_buckets() == 4000,
            "File rate-limit bucket capacity was not loaded"
        );

        require(
            config.trusted_proxy_cidrs().size() == 2,
            "Trusted proxy CIDRs were not loaded"
        );

        require(
            config.proxy_forwarded_header_max_bytes() == 2048,
            "Forwarded header limit was not loaded"
        );

        require(
            config.cors_allowed_origins().size() == 2,
            "CORS origins were not loaded"
        );

        require(
            config.cors_allow_credentials(),
            "CORS credentials setting was not loaded"
        );

        require(
            config.cors_max_age_seconds() == 300,
            "CORS max age was not loaded"
        );

        require(
            config.hsts_enabled() &&
            config.hsts_include_subdomains() &&
            !config.hsts_preload(),
            "HSTS settings were not loaded"
        );

        require(
            config.database_acquire_timeout_ms() == 250,
            "File database timeout was not loaded"
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
            "SECURECORE_DATABASE_POOL_SIZE",
            "5",
            1
        );

        ::setenv(
            "SECURECORE_DATABASE_ACQUIRE_TIMEOUT_MS",
            "750",
            1
        );

        ::setenv(
            "SECURECORE_SHUTDOWN_GRACE_PERIOD_MS",
            "2750",
            1
        );

        ::setenv(
            "SECURECORE_AUDIT_RETENTION_DAYS",
            "120",
            1
        );

        ::setenv(
            "SECURECORE_METRICS_REQUIRE_AUTH",
            "false",
            1
        );

        ::setenv(
            "SECURECORE_REGISTRATION_ENABLED",
            "false",
            1
        );

        ::setenv(
            "SECURECORE_AUTH_LOGIN_ACCOUNT_FAILURE_LIMIT",
            "6",
            1
        );

        ::setenv(
            "SECURECORE_AUTH_LOGIN_MAX_LOCKOUT_SECONDS",
            "240",
            1
        );

        ::setenv(
            "SECURECORE_AUTH_LOGIN_MAX_TRACKED_ACCOUNTS",
            "5000",
            1
        );

        ::setenv(
            "SECURECORE_AUTH_LOGIN_MAX_TRACKED_IPS",
            "6000",
            1
        );

        ::setenv(
            "SECURECORE_HTTP_RATE_LIMIT_MAX_BUCKETS",
            "7000",
            1
        );

        ::setenv(
            "SECURECORE_ENVIRONMENT",
            "test",
            1
        );

        ::setenv(
            "SECURECORE_TRUSTED_PROXY_CIDRS",
            "192.0.2.0/24",
            1
        );

        ::setenv(
            "SECURECORE_CORS_ALLOWED_ORIGINS",
            "https://override.example.com",
            1
        );

        ::setenv(
            "SECURECORE_CORS_ALLOW_CREDENTIALS",
            "false",
            1
        );

        ::setenv(
            "SECURECORE_HSTS_MAX_AGE_SECONDS",
            "63072000",
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
            config.database_pool_size() == 5,
            "Environment did not override database pool size"
        );

        require(
            config.database_acquire_timeout_ms() == 750,
            "Environment did not override database timeout"
        );

        require(
            config.environment() == "test",
            "Environment mode was not overridden"
        );

        require(
            config.shutdown_grace_period_ms() == 2750,
            "Environment did not override shutdown grace period"
        );

        require(
            config.audit_retention_days() == 120,
            "Environment did not override audit retention"
        );

        require(
            !config.metrics_require_auth(),
            "Environment did not override metrics authentication"
        );

        require(
            !config.registration_enabled(),
            "Environment did not override registration"
        );

        require(
            config.auth_login_account_failure_limit() == 6,
            "Environment did not override account failure limit"
        );

        require(
            config.auth_login_max_lockout_seconds() == 240,
            "Environment did not override maximum lockout"
        );

        require(
            config.auth_login_max_tracked_accounts() == 5000 &&
            config.auth_login_max_tracked_ips() == 6000,
            "Environment did not override authentication capacities"
        );

        require(
            config.http_rate_limit_max_buckets() == 7000,
            "Environment did not override rate-limit capacity"
        );

        require(
            config.trusted_proxy_cidrs().size() == 1 &&
            config.trusted_proxy_cidrs().front() == "192.0.2.0/24",
            "Environment did not override trusted proxies"
        );

        require(
            config.cors_allowed_origins().size() == 1 &&
            config.cors_allowed_origins().front() ==
                "https://override.example.com",
            "Environment did not override CORS origins"
        );

        require(
            !config.cors_allow_credentials(),
            "Environment did not override CORS credentials"
        );

        require(
            config.hsts_max_age_seconds() == 63072000,
            "Environment did not override HSTS max age"
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
        ::unsetenv("SECURECORE_DATABASE_POOL_SIZE");
        ::unsetenv("SECURECORE_DATABASE_ACQUIRE_TIMEOUT_MS");
        ::unsetenv("SECURECORE_SHUTDOWN_GRACE_PERIOD_MS");
        ::unsetenv("SECURECORE_AUDIT_RETENTION_DAYS");
        ::unsetenv("SECURECORE_METRICS_REQUIRE_AUTH");
        ::unsetenv("SECURECORE_AUTH_LOGIN_ACCOUNT_FAILURE_LIMIT");
        ::unsetenv("SECURECORE_AUTH_LOGIN_MAX_LOCKOUT_SECONDS");
        ::unsetenv("SECURECORE_ENVIRONMENT");
        ::unsetenv("SECURECORE_TRUSTED_PROXY_CIDRS");
        ::unsetenv("SECURECORE_CORS_ALLOWED_ORIGINS");
        ::unsetenv("SECURECORE_CORS_ALLOW_CREDENTIALS");
        ::unsetenv("SECURECORE_HSTS_MAX_AGE_SECONDS");

        write_file(
            config_path,
            base_config(root) +
            "auth_login_lockout_seconds=120\n"
            "auth_login_max_lockout_seconds=60\n"
        );

        require_throws(
            [&] {
                static_cast<void>(
                    secure::ServerConfig::load_from_file(
                        config_path.string()
                    )
                );
            },
            "auth_login_max_lockout_seconds"
        );

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

        write_file(
            config_path,
            base_config(root) +
            "cors_allowed_origins=*\n"
            "cors_allow_credentials=true\n"
        );

        require_throws(
            [&] {
                static_cast<void>(
                    secure::ServerConfig::load_from_file(
                        config_path.string()
                    )
                );
            },
            "cors_allow_credentials"
        );

        write_file(
            config_path,
            base_config(root) +
            "trusted_proxy_cidrs=10.0.0.0/99\n"
        );

        require_throws(
            [&] {
                static_cast<void>(
                    secure::ServerConfig::load_from_file(
                        config_path.string()
                    )
                );
            },
            "trusted_proxy_cidrs"
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
