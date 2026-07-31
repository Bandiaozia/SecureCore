#include "secure/net/connection_manager.hpp"

#include <vector>

namespace secure {

void ConnectionManager::start(
    const std::shared_ptr<Connection>& connection
) {
    connections_.insert(connection);
    connection->start();
}

void ConnectionManager::remove(
    const std::shared_ptr<Connection>& connection
) {
    connections_.erase(connection);
}

void ConnectionManager::stop_all() {
    std::vector<std::shared_ptr<Connection>>
        connections(
            connections_.begin(),
            connections_.end()
        );

    connections_.clear();

    for (const auto& connection : connections) {
        connection->stop();
    }
}

std::size_t
ConnectionManager::size() const noexcept {
    return connections_.size();
}

}  // namespace secure
