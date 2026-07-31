#pragma once

#include <cstdint>
#include <string>

namespace secure {

struct User final {
    std::int64_t id{0};

    std::string username;

    std::string email;

    std::string password_hash;

    std::string role;

    bool enabled{true};

    std::string created_at;

    std::string updated_at;
};

struct CreateUser final {
    std::string username;

    std::string email;

    std::string password_hash;

    std::string role{"user"};
};

}  // namespace secure
