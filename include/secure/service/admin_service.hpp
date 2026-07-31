#pragma once

#include "secure/model/user.hpp"

#include <cstdint>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace secure {

class AuthService;
class AuthSessionRepository;
class UserRepository;

enum class AdminErrorCode {
    forbidden,
    invalid_pagination,
    user_not_found,
    cannot_disable_self
};

[[nodiscard]]
std::string_view admin_error_name(
    AdminErrorCode code
) noexcept;

class AdminError final
    : public std::runtime_error {
public:
    AdminError(
        AdminErrorCode code,
        std::string message
    );

    [[nodiscard]]
    AdminErrorCode code()
        const noexcept;

private:
    AdminErrorCode code_;
};

struct UserListResult final {
    std::vector<User> users;

    std::int64_t total{0};

    std::int64_t limit{0};

    std::int64_t offset{0};
};

struct UserStatusResult final {
    User user;

    std::int64_t revoked_sessions{0};
};

class AdminService final {
public:
    AdminService(
        AuthService& auth_service,
        UserRepository& user_repository,
        AuthSessionRepository&
            auth_session_repository
    );

    [[nodiscard]]
    UserListResult list_users(
        std::string_view access_token,
        std::int64_t limit = 50,
        std::int64_t offset = 0
    );

    [[nodiscard]]
    UserStatusResult set_user_enabled(
        std::string_view access_token,
        std::int64_t target_user_id,
        bool enabled
    );

private:
    [[nodiscard]]
    User require_admin(
        std::string_view access_token
    );

    AuthService& auth_service_;

    UserRepository& user_repository_;

    AuthSessionRepository&
        auth_session_repository_;
};

}  // namespace secure
