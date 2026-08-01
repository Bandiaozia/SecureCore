#pragma once

#include "secure/model/rbac.hpp"

#include <cstdint>
#include <optional>
#include <stdexcept>
#include <string_view>
#include <vector>

namespace secure {

class Database;
class DatabaseTransaction;

class RbacRepositoryError
    : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

class RbacRoleNotFoundError final
    : public RbacRepositoryError {
public:
    using RbacRepositoryError::RbacRepositoryError;
};

class RbacRepository final {
public:
    explicit RbacRepository(Database& database);

    [[nodiscard]]
    std::vector<Role> list_roles();

    [[nodiscard]]
    std::vector<Permission> list_permissions();

    [[nodiscard]]
    std::vector<Role> roles_for_user(
        std::int64_t user_id
    );

    [[nodiscard]]
    std::vector<std::string> permission_names_for_user(
        std::int64_t user_id
    );

    [[nodiscard]]
    bool has_permission(
        std::int64_t user_id,
        std::string_view permission_name
    );

    [[nodiscard]]
    bool has_role(
        std::int64_t user_id,
        std::string_view role_name
    );

    [[nodiscard]]
    bool has_role(
        DatabaseTransaction& transaction,
        std::int64_t user_id,
        std::string_view role_name
    );

    [[nodiscard]]
    bool role_exists(
        std::string_view role_name
    );

    [[nodiscard]]
    std::int64_t count_enabled_users_with_role(
        std::string_view role_name
    );

    [[nodiscard]]
    std::int64_t count_enabled_users_with_role(
        DatabaseTransaction& transaction,
        std::string_view role_name
    );

    bool assign_role(
        std::int64_t user_id,
        std::string_view role_name,
        std::optional<std::int64_t> assigned_by = std::nullopt
    );

    bool assign_role(
        DatabaseTransaction& transaction,
        std::int64_t user_id,
        std::string_view role_name,
        std::optional<std::int64_t> assigned_by = std::nullopt
    );

    bool revoke_role(
        std::int64_t user_id,
        std::string_view role_name
    );

    bool revoke_role(
        DatabaseTransaction& transaction,
        std::int64_t user_id,
        std::string_view role_name
    );

private:
    Database& database_;
};

}  // namespace secure
