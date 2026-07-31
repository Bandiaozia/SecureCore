#pragma once

#include <cstdint>
#include <string>

namespace secure {

class ServerConfig final {
public:
    static ServerConfig load_from_file(
        const std::string& path
    );

    const std::string&
    listen_address() const noexcept;

    std::uint16_t
    listen_port() const noexcept;

    const std::string&
    log_file() const noexcept;

    std::uint32_t
    io_threads() const noexcept;

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
    std::string listen_address_{
        "0.0.0.0"
    };

    std::uint16_t listen_port_{8080};

    std::string log_file_{
        "logs/securecore.log"
    };

    std::uint32_t io_threads_{4};

    std::uint32_t
        http_max_connections_{1024};

    std::uint32_t
        http_rate_limit_requests_{100};

    std::uint32_t
        http_rate_limit_window_seconds_{1};

    std::uint32_t http_max_header_bytes_{
        16 * 1024
    };

    std::uint64_t http_max_body_bytes_{
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
