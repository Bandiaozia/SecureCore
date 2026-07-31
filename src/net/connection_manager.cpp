#include "secure/net/connection_manager.hpp"

#include <vector>

namespace secure {

void ConnectionManager::start(
    const std::shared_ptr<Connection>& connection
) {
    bool inserted = false;

    {
        std::scoped_lock lock(mutex_);

        inserted =
            connections_.insert(connection).second;
    }

    if (inserted) {
        connection->start();
    }
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

}  // namespace secure
