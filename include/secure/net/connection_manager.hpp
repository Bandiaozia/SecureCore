#pragma once

#include <cstddef>
#include <memory>
#include <unordered_set>

namespace secure {

class TcpSession;

class ConnectionManager final {
public:
    void start(const std::shared_ptr<TcpSession>& session);

    void remove(const std::shared_ptr<TcpSession>& session);

    void stop_all();

    std::size_t size() const noexcept;

private:
    std::unordered_set<std::shared_ptr<TcpSession>> sessions_;
};

}  // namespace secure
