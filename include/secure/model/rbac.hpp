#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace secure {

struct Permission final {
    std::int64_t id{0};
    std::string name;
    std::string description;
};

struct Role final {
    std::int64_t id{0};
    std::string name;
    std::string description;
    bool built_in{true};
    std::vector<Permission> permissions;
};

}  // namespace secure
