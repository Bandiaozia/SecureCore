#pragma once

#include "secure/model/user.hpp"

#include <cstdint>
#include <optional>
#include <stdexcept>
#include <string_view>
#include <vector>

namespace secure {

class Database;

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
    std::optional<User>
    find_by_username(
        std::string_view username
    );

    [[nodiscard]]
    std::optional<User>
    find_by_email(
        std::string_view email
    );

    /*
     * 登录时允许输入用户名或邮箱。
     */
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

    bool set_enabled(
        std::int64_t user_id,
        bool enabled
    );

private:
    Database& database_;
};

}  // namespace secure
