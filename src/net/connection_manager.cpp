#include "secure/net/connection_manager.hpp"

#include <stdexcept>
#include <vector>

namespace secure {

ConnectionManager::ConnectionManager(
    std::size_t max_connections
)
    : max_connections_(max_connections) {
    if (max_connections_ == 0) {
        throw std::invalid_argument(
            "max_connections must be greater than zero"
        );
    }
}

bool ConnectionManager::start(
    const std::shared_ptr<Connection>& connection
) {
    bool inserted = false;

    {
        std::scoped_lock lock(mutex_);

        if (
            connections_.size() >=
            max_connections_
        ) {
            return false;
        }

        inserted =
            connections_.insert(connection).second;
    }

    if (inserted) {
        connection->start();
    }

    return inserted;
}

void ConnectionManager::remove(
    const std::shared_ptr<Connection>& connection
) {
    std::scoped_lock lock(mutex_);

    connections_.erase(connection);
}

void ConnectionManager::stop_all() {
    std::vector<std::shared_ptr<Connection>>
        connections;

    {
        std::scoped_lock lock(mutex_);

        connections.assign(
            connections_.begin(),
            connections_.end()
        );

        connections_.clear();
    }

    for (const auto& connection : connections) {
        connection->stop();
    }
}

std::size_t ConnectionManager::size() const {
    std::scoped_lock lock(mutex_);

    return connections_.size();
}

std::size_t
ConnectionManager::capacity() const noexcept {
    return max_connections_;
}

bool ConnectionManager::full() const {
    std::scoped_lock lock(mutex_);

    return (
        connections_.size() >=
        max_connections_
    );
}

}  // namespace secure
