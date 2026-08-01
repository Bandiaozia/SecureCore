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
    bool became_empty = false;

    {
        std::scoped_lock lock(mutex_);

        connections_.erase(connection);
        became_empty = connections_.empty();
    }

    if (became_empty) {
        empty_condition_.notify_all();
    }
}

void ConnectionManager::drain_all() {
    std::vector<std::shared_ptr<Connection>>
        connections;

    {
        std::scoped_lock lock(mutex_);

        connections.assign(
            connections_.begin(),
            connections_.end()
        );
    }

    for (const auto& connection : connections) {
        connection->drain();
    }
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
    }

    for (const auto& connection : connections) {
        connection->stop();
    }
}

bool ConnectionManager::wait_until_empty(
    std::chrono::milliseconds timeout
) const {
    std::unique_lock lock(mutex_);

    return empty_condition_.wait_for(
        lock,
        timeout,
        [this] {
            return connections_.empty();
        }
    );
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
