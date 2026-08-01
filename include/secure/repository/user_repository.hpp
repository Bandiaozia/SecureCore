#pragma once

#include "secure/model/user.hpp"

#include <cstdint>
#include <optional>
#include <stdexcept>
#include <string_view>
#include <vector>

namespace secure {

class Database;
class DatabaseTransaction;

class UserRepositoryError
    : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

class DuplicateUserError final
    : public UserRepositoryError {
public:
    using UserRepositoryError::
        UserRepositoryError;
};

class UserRepository final {
public:
    explicit UserRepository(
        Database& database
    );

    [[nodiscard]]
    User create(
        const CreateUser& input
    );

    [[nodiscard]]
    std::optional<User> find_by_id(
        std::int64_t user_id
    );

    [[nodiscard]]
    std::optional<User> find_by_id(
        DatabaseTransaction& transaction,
        std::int64_t user_id
    );

    [[nodiscard]]
    std::optional<User>
    find_by_username(
        std::string_view username
    );

    [[nodiscard]]
    std::optional<User>
    find_by_email(
        std::string_view email
    );

    [[nodiscard]]
    std::optional<User>
    find_by_login(
        std::string_view login
    );

    [[nodiscard]]
    std::vector<User> list(
        std::int64_t limit,
        std::int64_t offset
    );

    [[nodiscard]]
    std::int64_t count();

    [[nodiscard]]
    std::int64_t count_enabled_admins();

    bool set_password_hash(
        std::int64_t user_id,
        std::string_view password_hash
    );

    bool set_password_hash(
        DatabaseTransaction& transaction,
        std::int64_t user_id,
        std::string_view password_hash
    );

    bool set_role(
        std::int64_t user_id,
        std::string_view role
    );

    bool set_enabled(
        std::int64_t user_id,
        bool enabled
    );

    bool set_enabled(
        DatabaseTransaction& transaction,
        std::int64_t user_id,
        bool enabled
    );

private:
    Database& database_;
};

}  // namespace secure
