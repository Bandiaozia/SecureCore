#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>

namespace secure {

struct HttpLimits final {
    std::uint32_t max_header_bytes{
        16 * 1024
    };

    std::uint64_t max_body_bytes{
        1024 * 1024
    };

    std::chrono::seconds read_timeout{10};

    std::chrono::seconds write_timeout{10};

    std::chrono::seconds idle_timeout{30};

    std::size_t max_connections{1024};

    std::chrono::seconds
        tls_handshake_timeout{10};
};

}  // namespace secure
