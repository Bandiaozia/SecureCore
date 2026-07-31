#pragma once

#include "secure/net/connection.hpp"

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

    void stop_all();

    std::size_t size() const;

    std::size_t capacity() const noexcept;

    bool full() const;

private:
    const std::size_t max_connections_;

    mutable std::mutex mutex_;

    std::unordered_set<
        std::shared_ptr<Connection>
    > connections_;
};

}  // namespace secure
