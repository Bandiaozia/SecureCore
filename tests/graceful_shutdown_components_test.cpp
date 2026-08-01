#include "secure/net/connection_manager.hpp"
#include "secure/runtime/service_state.hpp"

#include <atomic>
#include <chrono>
#include <cstdlib>
#include <iostream>
#include <memory>
#include <stdexcept>

namespace {

void require(
    bool condition,
    const char* message
) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

class FakeConnection final
    : public secure::Connection {
public:
    void start() override {
        starts.fetch_add(1);
    }

    void drain() override {
        drains.fetch_add(1);
    }

    void stop() override {
        stops.fetch_add(1);
    }

    std::atomic_int starts{0};
    std::atomic_int drains{0};
    std::atomic_int stops{0};
};

}  // namespace

int main() {
    try {
        secure::ServiceState state;

        require(
            state.phase() ==
                secure::ServicePhase::starting,
            "initial service phase"
        );

        state.mark_running();

        require(state.ready(), "running service ready");
        require(
            state.begin_draining(),
            "first draining transition"
        );
        require(
            !state.begin_draining(),
            "second draining transition"
        );
        require(
            !state.ready(),
            "draining service not ready"
        );
        require(
            secure::ServiceState::name(
                state.phase()
            ) == "draining",
            "draining phase name"
        );

        state.mark_stopped();

        require(
            state.phase() ==
                secure::ServicePhase::stopped,
            "stopped service phase"
        );

        secure::ConnectionManager manager(2);

        auto first =
            std::make_shared<FakeConnection>();
        auto second =
            std::make_shared<FakeConnection>();

        require(
            manager.start(first),
            "first connection start"
        );
        require(
            manager.start(second),
            "second connection start"
        );
        require(manager.full(), "manager full");
        require(
            first->starts.load() == 1 &&
            second->starts.load() == 1,
            "connection start callbacks"
        );

        manager.drain_all();

        require(
            first->drains.load() == 1 &&
            second->drains.load() == 1,
            "connection drain callbacks"
        );
        require(
            !manager.wait_until_empty(
                std::chrono::milliseconds{5}
            ),
            "non-empty manager wait timeout"
        );

        manager.remove(first);
        manager.remove(second);

        require(
            manager.wait_until_empty(
                std::chrono::milliseconds{5}
            ),
            "empty manager notification"
        );

        auto third =
            std::make_shared<FakeConnection>();

        require(
            manager.start(third),
            "third connection start"
        );

        manager.stop_all();

        require(
            third->stops.load() == 1,
            "connection stop callback"
        );

        manager.remove(third);

        require(
            manager.wait_until_empty(
                std::chrono::milliseconds{5}
            ),
            "manager empty after stopped connection removal"
        );

        std::cout
            << "Graceful shutdown component tests passed.\n";

        return EXIT_SUCCESS;
    } catch (const std::exception& error) {
        std::cerr
            << "Graceful shutdown component test failed: "
            << error.what()
            << '\n';

        return EXIT_FAILURE;
    }
}
