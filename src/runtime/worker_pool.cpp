#include "secure/runtime/worker_pool.hpp"

#include <stdexcept>
#include <utility>

namespace secure {

WorkerPool::WorkerPool(
    std::size_t thread_count,
    std::size_t queue_capacity
)
    : thread_count_(thread_count),
      queue_capacity_(queue_capacity) {
    if (thread_count_ == 0) {
        throw std::invalid_argument(
            "Worker thread count must "
            "be positive"
        );
    }

    if (queue_capacity_ == 0) {
        throw std::invalid_argument(
            "Worker queue capacity must "
            "be positive"
        );
    }

    workers_.reserve(thread_count_);

    try {
        for (
            std::size_t index = 0;
            index < thread_count_;
            ++index
        ) {
            workers_.emplace_back(
                [this] {
                    worker_loop();
                }
            );
        }
    } catch (...) {
        {
            std::scoped_lock lock(
                queue_mutex_
            );

            accepting_ = false;
            stopping_ = true;
        }

        condition_.notify_all();

        for (auto& worker : workers_) {
            if (worker.joinable()) {
                worker.join();
            }
        }

        throw;
    }
}

WorkerPool::~WorkerPool() {
    stop();
}

WorkerPool::SubmitResult
WorkerPool::try_submit(
    Task task
) {
    if (!task) {
        throw std::invalid_argument(
            "Worker task must not be empty"
        );
    }

    {
        std::scoped_lock lock(
            queue_mutex_
        );

        if (!accepting_) {
            rejected_tasks_.fetch_add(
                1,
                std::memory_order_relaxed
            );

            return SubmitResult::stopped;
        }

        if (
            tasks_.size() >=
            queue_capacity_
        ) {
            rejected_tasks_.fetch_add(
                1,
                std::memory_order_relaxed
            );

            return SubmitResult::queue_full;
        }

        tasks_.push_back(
            std::move(task)
        );

        queued_tasks_.fetch_add(
            1,
            std::memory_order_relaxed
        );
    }

    condition_.notify_one();

    return SubmitResult::accepted;
}

void WorkerPool::stop() noexcept {
    std::scoped_lock lifecycle_lock(
        stop_mutex_
    );

    {
        std::scoped_lock queue_lock(
            queue_mutex_
        );

        if (
            !accepting_ &&
            stopping_ &&
            workers_.empty()
        ) {
            return;
        }

        accepting_ = false;
        stopping_ = true;
    }

    condition_.notify_all();

    for (auto& worker : workers_) {
        if (worker.joinable()) {
            worker.join();
        }
    }

    workers_.clear();
}

std::size_t WorkerPool::thread_count()
    const noexcept {
    return thread_count_;
}

std::size_t WorkerPool::queue_capacity()
    const noexcept {
    return queue_capacity_;
}

WorkerPoolSnapshot WorkerPool::snapshot()
    const noexcept {
    return WorkerPoolSnapshot{
        thread_count_,
        queue_capacity_,
        queued_tasks_.load(
            std::memory_order_relaxed
        ),
        active_tasks_.load(
            std::memory_order_relaxed
        ),
        completed_tasks_.load(
            std::memory_order_relaxed
        ),
        rejected_tasks_.load(
            std::memory_order_relaxed
        )
    };
}

void WorkerPool::worker_loop() noexcept {
    while (true) {
        Task task;

        {
            std::unique_lock lock(
                queue_mutex_
            );

            condition_.wait(
                lock,
                [this] {
                    return (
                        stopping_ ||
                        !tasks_.empty()
                    );
                }
            );

            if (tasks_.empty()) {
                if (stopping_) {
                    return;
                }

                continue;
            }

            task = std::move(
                tasks_.front()
            );

            tasks_.pop_front();

            queued_tasks_.fetch_sub(
                1,
                std::memory_order_relaxed
            );

            active_tasks_.fetch_add(
                1,
                std::memory_order_relaxed
            );
        }

        try {
            task();
        } catch (...) {
        }

        active_tasks_.fetch_sub(
            1,
            std::memory_order_relaxed
        );

        completed_tasks_.fetch_add(
            1,
            std::memory_order_relaxed
        );
    }
}

}  // namespace secure
