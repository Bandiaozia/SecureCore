#pragma once

#include <atomic>
#include <cstdint>
#include <string_view>

namespace secure {

enum class ServicePhase : std::uint8_t {
    starting,
    running,
    draining,
    stopped
};

class ServiceState final {
public:
    ServiceState() noexcept = default;

    void mark_running() noexcept;

    [[nodiscard]]
    bool begin_draining() noexcept;

    void mark_stopped() noexcept;

    [[nodiscard]]
    ServicePhase phase() const noexcept;

    [[nodiscard]]
    bool ready() const noexcept;

    [[nodiscard]]
    static std::string_view name(
        ServicePhase phase
    ) noexcept;

private:
    std::atomic<ServicePhase> phase_{
        ServicePhase::starting
    };
};

}  // namespace secure
