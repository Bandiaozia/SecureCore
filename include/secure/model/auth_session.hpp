#pragma once

#include <cstdint>
#include <optional>
#include <string>

namespace secure {

struct AuthSession final {
    std::int64_t id{0};

    std::int64_t user_id{0};

    std::string access_token_hash;

    std::string refresh_token_hash;

    std::int64_t access_expires_at{0};

    std::int64_t refresh_expires_at{0};

    bool revoked{false};

    std::string created_at;

    std::optional<std::string>
        revoked_at;
};

struct CreateAuthSession final {
    std::int64_t user_id{0};

    std::string access_token_hash;

    std::string refresh_token_hash;

    std::int64_t access_expires_at{0};

    std::int64_t refresh_expires_at{0};
};

}  // namespace secure
