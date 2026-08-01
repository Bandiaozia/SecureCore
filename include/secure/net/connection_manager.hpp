#pragma once

#include "secure/net/connection.hpp"

#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <memory>
#include <mutex>
#include <unordered_set>

namespace secure {

class ConnectionManager final {
public:
    explicit ConnectionManager(
        std::size_t max_connections
    );

    bool start(
        const std::shared_ptr<Connection>& connection
    );

    void remove(
        const std::shared_ptr<Connection>& connection
    );

    void drain_all();

    void stop_all();

    [[nodiscard]]
    bool wait_until_empty(
        std::chrono::milliseconds timeout
    ) const;

    [[nodiscard]]
    std::size_t size() const;

    [[nodiscard]]
    std::size_t capacity() const noexcept;

    [[nodiscard]]
    bool full() const;

private:
    const std::size_t max_connections_;

    mutable std::mutex mutex_;

    mutable std::condition_variable empty_condition_;

    std::unordered_set<
        std::shared_ptr<Connection>
    > connections_;
};

}  // namespace secure
