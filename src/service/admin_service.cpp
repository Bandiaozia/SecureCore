#include "secure/service/admin_service.hpp"

#include "secure/database/database.hpp"
#include "secure/database/transaction.hpp"
#include "secure/repository/auth_session_repository.hpp"
#include "secure/repository/rbac_repository.hpp"
#include "secure/repository/user_repository.hpp"
#include "secure/service/auth_service.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>

namespace secure {

std::string_view admin_error_name(
    AdminErrorCode code
) noexcept {
    switch (code) {
    case AdminErrorCode::forbidden:
        return "permission_required";
    case AdminErrorCode::invalid_pagination:
        return "invalid_pagination";
    case AdminErrorCode::user_not_found:
        return "user_not_found";
    case AdminErrorCode::cannot_disable_self:
        return "cannot_disable_self";
    case AdminErrorCode::cannot_remove_last_super_admin:
        return "cannot_remove_last_super_admin";
    case AdminErrorCode::cannot_remove_base_role:
        return "cannot_remove_base_role";
    case AdminErrorCode::role_not_found:
        return "role_not_found";
    }
    return "admin_operation_failed";
}

AdminError::AdminError(
    AdminErrorCode code,
    std::string message
)
    : std::runtime_error(std::move(message)),
      code_(code) {
}

AdminErrorCode AdminError::code() const noexcept {
    return code_;
}

AdminService::AdminService(
    Database& database,
    AuthService& auth_service,
    UserRepository& user_repository,
    AuthSessionRepository& auth_session_repository,
    RbacRepository& rbac_repository
)
    : database_(database),
      auth_service_(auth_service),
      user_repository_(user_repository),
      auth_session_repository_(auth_session_repository),
      rbac_repository_(rbac_repository) {
}

User AdminService::authenticate_with_permission(
    std::string_view access_token,
    std::string_view permission
) {
    User user = auth_service_.authenticate_access_token(access_token);
    if (!rbac_repository_.has_permission(user.id, permission)) {
        throw AdminError(
            AdminErrorCode::forbidden,
            "Required permission is missing: " + std::string(permission)
        );
    }
    return user;
}

User AdminService::authenticate_admin(
    std::string_view access_token
) {
    return authenticate_with_permission(access_token, "users.read");
}

UserListResult AdminService::list_users(
    std::string_view access_token,
    std::int64_t limit,
    std::int64_t offset
) {
    static_cast<void>(
        authenticate_with_permission(access_token, "users.read")
    );
    if (limit <= 0 || limit > 100 || offset < 0) {
        throw AdminError(
            AdminErrorCode::invalid_pagination,
            "Invalid user list pagination"
        );
    }
    return UserListResult{
        user_repository_.list(limit, offset),
        user_repository_.count(),
        limit,
        offset
    };
}

User AdminService::get_user(
    std::string_view access_token,
    std::int64_t user_id
) {
    static_cast<void>(
        authenticate_with_permission(access_token, "users.read")
    );
    const std::optional<User> user = user_repository_.find_by_id(user_id);
    if (!user.has_value()) {
        throw AdminError(
            AdminErrorCode::user_not_found,
            "User does not exist"
        );
    }
    return *user;
}

UserStatusResult AdminService::set_user_enabled(
    std::string_view access_token,
    std::int64_t target_user_id,
    bool enabled
) {
    const User administrator = authenticate_with_permission(
        access_token,
        enabled ? "users.enable" : "users.disable"
    );

    if (!enabled && administrator.id == target_user_id) {
        throw AdminError(
            AdminErrorCode::cannot_disable_self,
            "Administrator cannot disable their own account"
        );
    }

    auto transaction = database_.begin_transaction();
    const std::optional<User> target = user_repository_.find_by_id(
        transaction, target_user_id
    );
    if (!target.has_value()) {
        throw AdminError(AdminErrorCode::user_not_found, "User does not exist");
    }

    if (
        !enabled &&
        target->enabled &&
        rbac_repository_.has_role(
            transaction, target_user_id, "super_admin"
        ) &&
        rbac_repository_.count_enabled_users_with_role(
            transaction, "super_admin"
        ) <= 1
    ) {
        throw AdminError(
            AdminErrorCode::cannot_remove_last_super_admin,
            "The last enabled super administrator cannot be disabled"
        );
    }

    if (!user_repository_.set_enabled(
            transaction, target_user_id, enabled
        )) {
        throw AdminError(AdminErrorCode::user_not_found, "User does not exist");
    }

    std::int64_t revoked_sessions = 0;
    if (!enabled) {
        revoked_sessions = auth_session_repository_.revoke_all_for_user(
            transaction, target_user_id
        );
    }

    const std::optional<User> updated_user = user_repository_.find_by_id(
        transaction, target_user_id
    );
    if (!updated_user.has_value()) {
        throw AdminError(
            AdminErrorCode::user_not_found,
            "Updated user could not be found"
        );
    }

    transaction.commit();
    return UserStatusResult{
        administrator.id,
        *updated_user,
        revoked_sessions
    };
}

std::vector<Role> AdminService::list_roles(
    std::string_view access_token
) {
    static_cast<void>(
        authenticate_with_permission(access_token, "roles.manage")
    );
    return rbac_repository_.list_roles();
}

std::vector<Permission> AdminService::list_permissions(
    std::string_view access_token
) {
    static_cast<void>(
        authenticate_with_permission(access_token, "roles.manage")
    );
    return rbac_repository_.list_permissions();
}

std::vector<Role> AdminService::list_user_roles(
    std::string_view access_token,
    std::int64_t user_id
) {
    static_cast<void>(
        authenticate_with_permission(access_token, "roles.manage")
    );
    if (!user_repository_.find_by_id(user_id).has_value()) {
        throw AdminError(AdminErrorCode::user_not_found, "User does not exist");
    }
    return rbac_repository_.roles_for_user(user_id);
}

RoleChangeResult AdminService::assign_role(
    std::string_view access_token,
    std::int64_t target_user_id,
    std::string role_name
) {
    const User administrator = authenticate_with_permission(
        access_token, "roles.manage"
    );
    auto transaction = database_.begin_transaction();
    const std::optional<User> target = user_repository_.find_by_id(
        transaction, target_user_id
    );
    if (!target.has_value()) {
        throw AdminError(AdminErrorCode::user_not_found, "User does not exist");
    }

    bool changed = false;
    try {
        changed = rbac_repository_.assign_role(
            transaction,
            target_user_id,
            role_name,
            administrator.id
        );
    } catch (const RbacRoleNotFoundError&) {
        throw AdminError(AdminErrorCode::role_not_found, "Role does not exist");
    }

    const std::optional<User> updated = user_repository_.find_by_id(
        transaction, target_user_id
    );
    if (!updated.has_value()) {
        throw AdminError(AdminErrorCode::user_not_found, "User does not exist");
    }
    transaction.commit();

    return RoleChangeResult{
        administrator.id,
        *updated,
        rbac_repository_.roles_for_user(target_user_id),
        changed
    };
}

RoleChangeResult AdminService::revoke_role(
    std::string_view access_token,
    std::int64_t target_user_id,
    std::string role_name
) {
    const User administrator = authenticate_with_permission(
        access_token, "roles.manage"
    );
    if (role_name == "user") {
        throw AdminError(
            AdminErrorCode::cannot_remove_base_role,
            "The base user role cannot be removed"
        );
    }

    auto transaction = database_.begin_transaction();
    const std::optional<User> target = user_repository_.find_by_id(
        transaction, target_user_id
    );
    if (!target.has_value()) {
        throw AdminError(AdminErrorCode::user_not_found, "User does not exist");
    }

    try {
        if (
            role_name == "super_admin" &&
            target->enabled &&
            rbac_repository_.has_role(
                transaction, target_user_id, role_name
            ) &&
            rbac_repository_.count_enabled_users_with_role(
                transaction, role_name
            ) <= 1
        ) {
            throw AdminError(
                AdminErrorCode::cannot_remove_last_super_admin,
                "The last enabled super administrator cannot be removed"
            );
        }

        const bool changed = rbac_repository_.revoke_role(
            transaction, target_user_id, role_name
        );
        const std::optional<User> updated = user_repository_.find_by_id(
            transaction, target_user_id
        );
        if (!updated.has_value()) {
            throw AdminError(AdminErrorCode::user_not_found, "User does not exist");
        }
        transaction.commit();

        return RoleChangeResult{
            administrator.id,
            *updated,
            rbac_repository_.roles_for_user(target_user_id),
            changed
        };
    } catch (const RbacRoleNotFoundError&) {
        throw AdminError(AdminErrorCode::role_not_found, "Role does not exist");
    }
}

}  // namespace secure
