#pragma once

#include <condition_variable>
#include <cstddef>
#include <deque>
#include <functional>
#include <mutex>
#include <thread>
#include <vector>

namespace secure {

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

    /*
     * 停止接收新任务，处理完队列中已有任务，
     * 然后等待全部工作线程退出。
     *
     * 该函数可以安全地重复调用。
     */
    void stop() noexcept;

    [[nodiscard]]
    std::size_t thread_count()
        const noexcept;

    [[nodiscard]]
    std::size_t queue_capacity()
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

    /*
     * 防止多个线程同时执行 join。
     */
    std::mutex stop_mutex_;
};

}  // namespace secure
