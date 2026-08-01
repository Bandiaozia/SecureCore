#pragma once

#include <atomic>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <functional>
#include <mutex>
#include <thread>
#include <vector>

namespace secure {

struct WorkerPoolSnapshot final {
    std::size_t thread_count{0};

    std::size_t queue_capacity{0};

    std::uint64_t queued_tasks{0};

    std::uint64_t active_tasks{0};

    std::uint64_t completed_tasks{0};

    std::uint64_t rejected_tasks{0};
};

class WorkerPool final {
public:
    using Task = std::function<void()>;

    enum class SubmitResult {
        accepted,
        queue_full,
        stopped
    };

    WorkerPool(
        std::size_t thread_count,
        std::size_t queue_capacity
    );

    ~WorkerPool();

    WorkerPool(const WorkerPool&) = delete;

    WorkerPool& operator=(
        const WorkerPool&
    ) = delete;

    [[nodiscard]]
    SubmitResult try_submit(
        Task task
    );

    void stop() noexcept;

    [[nodiscard]]
    std::size_t thread_count()
        const noexcept;

    [[nodiscard]]
    std::size_t queue_capacity()
        const noexcept;

    [[nodiscard]]
    WorkerPoolSnapshot snapshot()
        const noexcept;

private:
    void worker_loop() noexcept;

    const std::size_t thread_count_;

    const std::size_t queue_capacity_;

    std::vector<std::thread> workers_;

    std::deque<Task> tasks_;

    std::mutex queue_mutex_;

    std::condition_variable condition_;

    bool accepting_{true};

    bool stopping_{false};

    std::mutex stop_mutex_;

    std::atomic_uint64_t queued_tasks_{0};

    std::atomic_uint64_t active_tasks_{0};

    std::atomic_uint64_t completed_tasks_{0};

    std::atomic_uint64_t rejected_tasks_{0};
};

}  // namespace secure
