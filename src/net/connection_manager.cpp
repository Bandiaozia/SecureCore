#include "secure/net/connection_manager.hpp"

#include "secure/net/tcp_session.hpp"

#include <vector>

namespace secure {

void ConnectionManager::start(
    const std::shared_ptr<TcpSession>& session
) {
    sessions_.insert(session);
    session->start();
}

void ConnectionManager::remove(
    const std::shared_ptr<TcpSession>& session
) {
    sessions_.erase(session);
}

void ConnectionManager::stop_all() {
    std::vector<std::shared_ptr<TcpSession>> sessions(
        sessions_.begin(),
        sessions_.end()
    );

    sessions_.clear();

    for (const auto& session : sessions) {
        session->stop();
    }
}

std::size_t ConnectionManager::size() const noexcept {
    return sessions_.size();
}

}  // namespace secure
