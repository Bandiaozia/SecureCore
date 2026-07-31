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

    std::uint16_t listen_port() const noexcept;

    const std::string&
    log_file() const noexcept;

private:
    std::string listen_address_{"0.0.0.0"};

    std::uint16_t listen_port_{8080};

    std::string log_file_{
        "logs/securecore.log"
    };
};

}  // namespace secure
