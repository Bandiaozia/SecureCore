#include "secure/runtime/service_state.hpp"

namespace secure {

void ServiceState::mark_running() noexcept {
    phase_.store(
        ServicePhase::running,
        std::memory_order_release
    );
}

bool ServiceState::begin_draining() noexcept {
    ServicePhase current = phase_.load(
        std::memory_order_acquire
    );

    while (
        current != ServicePhase::draining &&
        current != ServicePhase::stopped
    ) {
        if (
            phase_.compare_exchange_weak(
                current,
                ServicePhase::draining,
                std::memory_order_acq_rel,
                std::memory_order_acquire
            )
        ) {
            return true;
        }
    }

    return false;
}

void ServiceState::mark_stopped() noexcept {
    phase_.store(
        ServicePhase::stopped,
        std::memory_order_release
    );
}

ServicePhase ServiceState::phase() const noexcept {
    return phase_.load(
        std::memory_order_acquire
    );
}

bool ServiceState::ready() const noexcept {
    return phase() == ServicePhase::running;
}

std::string_view ServiceState::name(
    ServicePhase phase
) noexcept {
    switch (phase) {
        case ServicePhase::starting:
            return "starting";
        case ServicePhase::running:
            return "running";
        case ServicePhase::draining:
            return "draining";
        case ServicePhase::stopped:
            return "stopped";
    }

    return "unknown";
}

}  // namespace secure
