#pragma once

#include <cstdint>
#include <string>
#include <string_view>

namespace secure {

class ServerConfig final {
public:
    static ServerConfig load_from_file(
        const std::string& path
    );

    void validate_for_server() const;

    void validate_for_admin() const;

    std::string redacted_summary() const;

    const std::string&
    environment() const noexcept;

    const std::string&
    listen_address() const noexcept;

    std::uint16_t
    listen_port() const noexcept;

    const std::string&
    log_file() const noexcept;

    const std::string&
    database_path() const noexcept;

    std::uint32_t
    io_threads() const noexcept;

    std::uint32_t
    worker_threads() const noexcept;

    std::uint32_t
    worker_queue_capacity() const noexcept;

    bool tls_enabled() const noexcept;

    const std::string&
    tls_certificate_file() const noexcept;

    const std::string&
    tls_private_key_file() const noexcept;

    std::uint32_t
    tls_handshake_timeout_seconds()
        const noexcept;

    std::uint32_t
    http_max_connections() const noexcept;

    std::uint32_t
    http_rate_limit_requests() const noexcept;

    std::uint32_t
    http_rate_limit_window_seconds() const noexcept;

    std::uint32_t
    http_max_header_bytes() const noexcept;

    std::uint64_t
    http_max_body_bytes() const noexcept;

    std::uint32_t
    http_read_timeout_seconds() const noexcept;

    std::uint32_t
    http_write_timeout_seconds() const noexcept;

    std::uint32_t
    http_idle_timeout_seconds() const noexcept;

private:
    void apply_setting(
        std::string_view key,
        const std::string& value,
        std::string_view source
    );

    void apply_environment_overrides();

    void validate_common() const;

    std::string environment_{
        "development"
    };

    std::string listen_address_{
        "0.0.0.0"
    };

    std::uint16_t listen_port_{8080};

    std::string log_file_{
        "logs/securecore.log"
    };

    std::string database_path_{
        "data/securecore.db"
    };

    std::uint32_t io_threads_{4};

    std::uint32_t worker_threads_{4};

    std::uint32_t
        worker_queue_capacity_{256};

    bool tls_enabled_{false};

    std::string tls_certificate_file_;

    std::string tls_private_key_file_;

    std::uint32_t
        tls_handshake_timeout_seconds_{10};

    std::uint32_t
        http_max_connections_{1024};

    std::uint32_t
        http_rate_limit_requests_{100};

    std::uint32_t
        http_rate_limit_window_seconds_{1};

    std::uint32_t
        http_max_header_bytes_{
            16 * 1024
        };

    std::uint64_t
        http_max_body_bytes_{
            1024 * 1024
        };

    std::uint32_t
        http_read_timeout_seconds_{10};

    std::uint32_t
        http_write_timeout_seconds_{10};

    std::uint32_t
        http_idle_timeout_seconds_{30};
};

}  // namespace secure
