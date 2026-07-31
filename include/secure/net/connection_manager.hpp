#pragma once

#include "secure/net/connection.hpp"

#include <cstddef>
#include <memory>
#include <mutex>
#include <unordered_set>

namespace secure {

class ConnectionManager final {
public:
    void start(
        const std::shared_ptr<Connection>& connection
    );

    void remove(
        const std::shared_ptr<Connection>& connection
    );

    void stop_all();

    std::size_t size() const;

private:
    mutable std::mutex mutex_;

    std::unordered_set<
        std::shared_ptr<Connection>
    > connections_;
};

}  // namespace secure
