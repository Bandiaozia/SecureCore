#pragma once

#include "secure/model/rbac.hpp"
#include "secure/model/user.hpp"

#include <cstdint>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace secure {

class AuthService;
class Database;
class AuthSessionRepository;
class RbacRepository;
class UserRepository;

enum class AdminErrorCode {
    forbidden,
    invalid_pagination,
    user_not_found,
    cannot_disable_self,
    cannot_remove_last_super_admin,
    cannot_remove_base_role,
    role_not_found
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
    AdminErrorCode code() const noexcept;

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
    std::int64_t administrator_id{0};
    User user;
    std::int64_t revoked_sessions{0};
};

struct RoleChangeResult final {
    std::int64_t administrator_id{0};
    User user;
    std::vector<Role> roles;
    bool changed{false};
};

class AdminService final {
public:
    AdminService(
        Database& database,
        AuthService& auth_service,
        UserRepository& user_repository,
        AuthSessionRepository& auth_session_repository,
        RbacRepository& rbac_repository
    );

    [[nodiscard]]
    User authenticate_admin(
        std::string_view access_token
    );

    [[nodiscard]]
    User authenticate_with_permission(
        std::string_view access_token,
        std::string_view permission
    );

    [[nodiscard]]
    UserListResult list_users(
        std::string_view access_token,
        std::int64_t limit = 50,
        std::int64_t offset = 0
    );

    [[nodiscard]]
    User get_user(
        std::string_view access_token,
        std::int64_t user_id
    );

    [[nodiscard]]
    UserStatusResult set_user_enabled(
        std::string_view access_token,
        std::int64_t target_user_id,
        bool enabled
    );

    [[nodiscard]]
    std::vector<Role> list_roles(
        std::string_view access_token
    );

    [[nodiscard]]
    std::vector<Permission> list_permissions(
        std::string_view access_token
    );

    [[nodiscard]]
    std::vector<Role> list_user_roles(
        std::string_view access_token,
        std::int64_t user_id
    );

    [[nodiscard]]
    RoleChangeResult assign_role(
        std::string_view access_token,
        std::int64_t target_user_id,
        std::string role_name
    );

    [[nodiscard]]
    RoleChangeResult revoke_role(
        std::string_view access_token,
        std::int64_t target_user_id,
        std::string role_name
    );

private:
    Database& database_;
    AuthService& auth_service_;
    UserRepository& user_repository_;
    AuthSessionRepository& auth_session_repository_;
    RbacRepository& rbac_repository_;
};

}  // namespace secure
