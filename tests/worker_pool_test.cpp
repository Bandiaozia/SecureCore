#include "secure/runtime/worker_pool.hpp"

#include <atomic>
#include <cstdlib>
#include <future>
#include <iostream>

namespace {

void require(
    bool condition,
    const char* message
) {
    if (condition) {
        return;
    }

    std::cerr
        << "WorkerPool test failed: "
        << message
        << '\n';

    std::exit(EXIT_FAILURE);
}

}  // namespace

int main() {
    secure::WorkerPool pool(
        1,
        1
    );

    std::promise<void> first_started;
    std::promise<void> release_first;

    std::shared_future<void> release_signal =
        release_first
            .get_future()
            .share();

    std::atomic_int executed{0};

    const auto first =
        pool.try_submit(
            [
                &first_started,
                release_signal,
                &executed
            ] {
                first_started.set_value();
                release_signal.wait();
                ++executed;
            }
        );

    require(
        first ==
            secure::WorkerPool::
                SubmitResult::accepted,
        "first task must be accepted"
    );

    first_started
        .get_future()
        .wait();

    const auto second =
        pool.try_submit(
            [&executed] {
                ++executed;
            }
        );

    require(
        second ==
            secure::WorkerPool::
                SubmitResult::accepted,
        "second task must enter queue"
    );

    const auto busy_snapshot =
        pool.snapshot();

    require(
        busy_snapshot.active_tasks == 1,
        "one task must be active"
    );

    require(
        busy_snapshot.queued_tasks == 1,
        "one task must be queued"
    );

    const auto third =
        pool.try_submit(
            [] {
            }
        );

    require(
        third ==
            secure::WorkerPool::
                SubmitResult::queue_full,
        "third task must be rejected"
    );

    require(
        pool.snapshot().rejected_tasks == 1,
        "queue rejection metric"
    );

    release_first.set_value();
    pool.stop();

    require(
        executed.load() == 2,
        "stop must drain accepted tasks"
    );

    const auto drained =
        pool.snapshot();

    require(
        drained.active_tasks == 0 &&
        drained.queued_tasks == 0,
        "pool must be idle after stop"
    );

    require(
        drained.completed_tasks == 2,
        "completed task metric"
    );

    const auto after_stop =
        pool.try_submit(
            [] {
            }
        );

    require(
        after_stop ==
            secure::WorkerPool::
                SubmitResult::stopped,
        "submission after stop must fail"
    );

    require(
        pool.snapshot().rejected_tasks == 2,
        "stopped rejection metric"
    );

    std::cout
        << "WorkerPool tests passed\n";

    return EXIT_SUCCESS;
}
