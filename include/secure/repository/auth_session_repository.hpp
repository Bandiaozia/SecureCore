#pragma once

#include "secure/model/auth_session.hpp"

#include <cstdint>
#include <optional>
#include <stdexcept>
#include <string_view>
#include <vector>

namespace secure {

class Database;
class DatabaseTransaction;

class AuthSessionRepositoryError
    : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

class DuplicateTokenError final
    : public AuthSessionRepositoryError {
public:
    using AuthSessionRepositoryError::
        AuthSessionRepositoryError;
};

class AuthSessionRepository final {
public:
    explicit AuthSessionRepository(
        Database& database
    );

    [[nodiscard]]
    AuthSession create(
        const CreateAuthSession& input
    );

    [[nodiscard]]
    AuthSession create(
        DatabaseTransaction& transaction,
        const CreateAuthSession& input
    );

    [[nodiscard]]
    std::optional<AuthSession>
    find_by_access_token_hash(
        std::string_view token_hash
    );

    [[nodiscard]]
    std::optional<AuthSession>
    find_by_refresh_token_hash(
        std::string_view token_hash
    );

    [[nodiscard]]
    std::optional<AuthSession>
    find_by_refresh_token_hash(
        DatabaseTransaction& transaction,
        std::string_view token_hash
    );

    [[nodiscard]]
    std::vector<AuthSession>
    list_active_for_user(
        std::int64_t user_id,
        std::int64_t current_time
    );

    [[nodiscard]]
    std::optional<AuthSession>
    find_by_id_for_user(
        std::int64_t session_id,
        std::int64_t user_id
    );

    bool revoke_by_id_for_user(
        std::int64_t session_id,
        std::int64_t user_id
    );

    std::int64_t
    revoke_all_except_for_user(
        std::int64_t user_id,
        std::int64_t excluded_session_id
    );

    [[nodiscard]]
    std::int64_t
    revoke_all_except_for_user(
        DatabaseTransaction& transaction,
        std::int64_t user_id,
        std::int64_t excluded_session_id
    );

    bool revoke_by_id(
        std::int64_t session_id
    );

    bool revoke_by_id(
        DatabaseTransaction& transaction,
        std::int64_t session_id
    );

    bool revoke_by_refresh_token_hash(
        std::string_view token_hash
    );

    std::int64_t revoke_all_for_user(
        std::int64_t user_id
    );

    [[nodiscard]]
    std::int64_t revoke_all_for_user(
        DatabaseTransaction& transaction,
        std::int64_t user_id
    );

    [[nodiscard]]
    std::int64_t revoke_family(
        DatabaseTransaction& transaction,
        std::string_view token_family_id
    );

    std::int64_t delete_expired(
        std::int64_t current_time
    );

private:
    Database& database_;
};

}  // namespace secure
