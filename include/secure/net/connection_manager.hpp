#pragma once

#include <cstddef>
#include <memory>
#include <unordered_set>

#include "secure/net/connection.hpp"

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

    std::size_t size() const noexcept;

private:
    std::unordered_set<
        std::shared_ptr<Connection>
    > connections_;
};

}  // namespace secure
