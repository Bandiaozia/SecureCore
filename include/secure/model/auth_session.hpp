#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <utility>

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

    std::string token_family_id;

    std::optional<std::int64_t>
        parent_session_id;
};

struct CreateAuthSession final {
    CreateAuthSession() = default;

    CreateAuthSession(
        std::int64_t user_identifier,
        std::string access_hash,
        std::string refresh_hash,
        std::int64_t access_expiry,
        std::int64_t refresh_expiry,
        std::string family_id = {},
        std::optional<std::int64_t> parent_id =
            std::nullopt
    )
        : user_id(user_identifier),
          access_token_hash(std::move(access_hash)),
          refresh_token_hash(std::move(refresh_hash)),
          access_expires_at(access_expiry),
          refresh_expires_at(refresh_expiry),
          token_family_id(std::move(family_id)),
          parent_session_id(parent_id) {
    }

    std::int64_t user_id{0};

    std::string access_token_hash;

    std::string refresh_token_hash;

    std::int64_t access_expires_at{0};

    std::int64_t refresh_expires_at{0};

    std::string token_family_id;

    std::optional<std::int64_t>
        parent_session_id;
};

}  // namespace secure
