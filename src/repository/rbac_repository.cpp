#include "secure/repository/rbac_repository.hpp"

#include "secure/database/database.hpp"
#include "secure/database/transaction.hpp"

#include <cstdint>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <sqlite3.h>

namespace secure {

namespace {

std::string sqlite_error(
    sqlite3* handle,
    std::string_view operation,
    int result
) {
    std::ostringstream message;
    message << operation
            << " failed with SQLite code "
            << result << ": "
            << sqlite3_errmsg(handle);
    return message.str();
}

class Statement final {
public:
    Statement(sqlite3* handle, std::string_view sql)
        : handle_(handle) {
        const std::string text(sql);
        const int result = sqlite3_prepare_v2(
            handle_, text.c_str(),
            static_cast<int>(text.size()),
            &statement_, nullptr
        );
        if (result != SQLITE_OK) {
            throw RbacRepositoryError(
                sqlite_error(handle_, "Preparing RBAC query", result)
            );
        }
    }

    ~Statement() {
        if (statement_ != nullptr) {
            sqlite3_finalize(statement_);
        }
    }

    Statement(const Statement&) = delete;
    Statement& operator=(const Statement&) = delete;

    void bind_int64(int index, std::int64_t value) {
        check(sqlite3_bind_int64(statement_, index, value));
    }

    void bind_optional_int64(
        int index,
        std::optional<std::int64_t> value
    ) {
        if (value.has_value()) {
            bind_int64(index, *value);
            return;
        }
        check(sqlite3_bind_null(statement_, index));
    }

    void bind_text(int index, std::string_view value) {
        check(sqlite3_bind_text(
            statement_, index, value.data(),
            static_cast<int>(value.size()), SQLITE_TRANSIENT
        ));
    }

    int step() {
        return sqlite3_step(statement_);
    }

    [[nodiscard]]
    std::int64_t column_int64(int index) const {
        return sqlite3_column_int64(statement_, index);
    }

    [[nodiscard]]
    bool column_bool(int index) const {
        return sqlite3_column_int(statement_, index) != 0;
    }

    [[nodiscard]]
    std::string column_text(int index) const {
        const auto* value = sqlite3_column_text(statement_, index);
        if (value == nullptr) {
            return {};
        }
        const int bytes = sqlite3_column_bytes(statement_, index);
        return {
            reinterpret_cast<const char*>(value),
            static_cast<std::size_t>(bytes)
        };
    }

private:
    void check(int result) {
        if (result != SQLITE_OK) {
            throw RbacRepositoryError(
                sqlite_error(handle_, "Binding RBAC query", result)
            );
        }
    }

    sqlite3* handle_{nullptr};
    sqlite3_stmt* statement_{nullptr};
};

std::int64_t require_role_id(
    sqlite3* handle,
    std::string_view role_name
) {
    Statement statement{
        handle,
        "SELECT id FROM roles WHERE name = ?1 LIMIT 1;"
    };
    statement.bind_text(1, role_name);
    const int result = statement.step();
    if (result == SQLITE_ROW) {
        return statement.column_int64(0);
    }
    if (result == SQLITE_DONE) {
        throw RbacRoleNotFoundError(
            "RBAC role does not exist: " + std::string(role_name)
        );
    }
    throw RbacRepositoryError(
        sqlite_error(handle, "Reading RBAC role", result)
    );
}

bool user_exists(sqlite3* handle, std::int64_t user_id) {
    Statement statement{
        handle,
        "SELECT 1 FROM users WHERE id = ?1 LIMIT 1;"
    };
    statement.bind_int64(1, user_id);
    const int result = statement.step();
    if (result == SQLITE_ROW) {
        return true;
    }
    if (result == SQLITE_DONE) {
        return false;
    }
    throw RbacRepositoryError(
        sqlite_error(handle, "Checking RBAC user", result)
    );
}

std::vector<Permission> permissions_for_role_locked(
    sqlite3* handle,
    std::int64_t role_id
) {
    Statement statement{
        handle,
        R"SQL(
SELECT p.id, p.name, p.description
FROM permissions AS p
JOIN role_permissions AS rp
    ON rp.permission_id = p.id
WHERE rp.role_id = ?1
ORDER BY p.name ASC;
)SQL"
    };
    statement.bind_int64(1, role_id);

    std::vector<Permission> permissions;
    while (true) {
        const int result = statement.step();
        if (result == SQLITE_ROW) {
            permissions.push_back(Permission{
                statement.column_int64(0),
                statement.column_text(1),
                statement.column_text(2)
            });
            continue;
        }
        if (result == SQLITE_DONE) {
            break;
        }
        throw RbacRepositoryError(
            sqlite_error(handle, "Listing role permissions", result)
        );
    }
    return permissions;
}

std::vector<Role> list_roles_locked(sqlite3* handle) {
    Statement statement{
        handle,
        R"SQL(
SELECT id, name, description, built_in
FROM roles
ORDER BY CASE name
    WHEN 'user' THEN 0
    WHEN 'auditor' THEN 1
    WHEN 'support' THEN 2
    WHEN 'security_admin' THEN 3
    WHEN 'super_admin' THEN 4
    ELSE 100
END, name ASC;
)SQL"
    };

    std::vector<Role> roles;
    while (true) {
        const int result = statement.step();
        if (result == SQLITE_ROW) {
            Role role{
                statement.column_int64(0),
                statement.column_text(1),
                statement.column_text(2),
                statement.column_bool(3),
                {}
            };
            role.permissions = permissions_for_role_locked(
                handle, role.id
            );
            roles.push_back(std::move(role));
            continue;
        }
        if (result == SQLITE_DONE) {
            break;
        }
        throw RbacRepositoryError(
            sqlite_error(handle, "Listing RBAC roles", result)
        );
    }
    return roles;
}

std::vector<Role> roles_for_user_locked(
    sqlite3* handle,
    std::int64_t user_id
) {
    Statement statement{
        handle,
        R"SQL(
SELECT r.id, r.name, r.description, r.built_in
FROM roles AS r
JOIN user_roles AS ur ON ur.role_id = r.id
WHERE ur.user_id = ?1
ORDER BY CASE r.name
    WHEN 'user' THEN 0
    WHEN 'auditor' THEN 1
    WHEN 'support' THEN 2
    WHEN 'security_admin' THEN 3
    WHEN 'super_admin' THEN 4
    ELSE 100
END, r.name ASC;
)SQL"
    };
    statement.bind_int64(1, user_id);

    std::vector<Role> roles;
    while (true) {
        const int result = statement.step();
        if (result == SQLITE_ROW) {
            Role role{
                statement.column_int64(0),
                statement.column_text(1),
                statement.column_text(2),
                statement.column_bool(3),
                {}
            };
            role.permissions = permissions_for_role_locked(
                handle, role.id
            );
            roles.push_back(std::move(role));
            continue;
        }
        if (result == SQLITE_DONE) {
            break;
        }
        throw RbacRepositoryError(
            sqlite_error(handle, "Listing user roles", result)
        );
    }
    return roles;
}

bool assign_role_locked(
    sqlite3* handle,
    std::int64_t user_id,
    std::string_view role_name,
    std::optional<std::int64_t> assigned_by
) {
    if (!user_exists(handle, user_id)) {
        return false;
    }

    const std::int64_t role_id = require_role_id(handle, role_name);

    Statement statement{
        handle,
        R"SQL(
INSERT OR IGNORE INTO user_roles (
    user_id,
    role_id,
    assigned_by_user_id
)
VALUES (?1, ?2, ?3);
)SQL"
    };
    statement.bind_int64(1, user_id);
    statement.bind_int64(2, role_id);
    statement.bind_optional_int64(3, assigned_by);

    const int result = statement.step();
    if (result != SQLITE_DONE) {
        throw RbacRepositoryError(
            sqlite_error(handle, "Assigning RBAC role", result)
        );
    }

    const bool changed = sqlite3_changes(handle) > 0;

    if (role_name == "super_admin") {
        Statement legacy{
            handle,
            R"SQL(
UPDATE users
SET role = 'admin',
    updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
WHERE id = ?1 AND role <> 'admin';
)SQL"
        };
        legacy.bind_int64(1, user_id);
        const int legacy_result = legacy.step();
        if (legacy_result != SQLITE_DONE) {
            throw RbacRepositoryError(
                sqlite_error(handle, "Updating legacy administrator role", legacy_result)
            );
        }
    }

    return changed;
}

bool revoke_role_locked(
    sqlite3* handle,
    std::int64_t user_id,
    std::string_view role_name
) {
    const std::int64_t role_id = require_role_id(handle, role_name);

    Statement statement{
        handle,
        "DELETE FROM user_roles WHERE user_id = ?1 AND role_id = ?2;"
    };
    statement.bind_int64(1, user_id);
    statement.bind_int64(2, role_id);
    const int result = statement.step();
    if (result != SQLITE_DONE) {
        throw RbacRepositoryError(
            sqlite_error(handle, "Revoking RBAC role", result)
        );
    }

    const bool changed = sqlite3_changes(handle) > 0;

    if (role_name == "super_admin") {
        Statement check{
            handle,
            R"SQL(
SELECT 1
FROM user_roles AS ur
JOIN roles AS r ON r.id = ur.role_id
WHERE ur.user_id = ?1 AND r.name = 'super_admin'
LIMIT 1;
)SQL"
        };
        check.bind_int64(1, user_id);
        const int check_result = check.step();
        if (check_result == SQLITE_DONE) {
            Statement legacy{
                handle,
                R"SQL(
UPDATE users
SET role = 'user',
    updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
WHERE id = ?1 AND role <> 'user';
)SQL"
            };
            legacy.bind_int64(1, user_id);
            const int legacy_result = legacy.step();
            if (legacy_result != SQLITE_DONE) {
                throw RbacRepositoryError(
                    sqlite_error(handle, "Updating legacy user role", legacy_result)
                );
            }
        } else if (check_result != SQLITE_ROW) {
            throw RbacRepositoryError(
                sqlite_error(handle, "Checking remaining super-admin role", check_result)
            );
        }
    }

    return changed;
}

}  // namespace

RbacRepository::RbacRepository(Database& database)
    : database_(database) {
}

std::vector<Role> RbacRepository::list_roles() {
    return database_.with_locked_handle(
        [](sqlite3* handle) {
            return list_roles_locked(handle);
        }
    );
}

std::vector<Permission> RbacRepository::list_permissions() {
    return database_.with_locked_handle(
        [](sqlite3* handle) {
            Statement statement{
                handle,
                "SELECT id, name, description FROM permissions ORDER BY name ASC;"
            };
            std::vector<Permission> permissions;
            while (true) {
                const int result = statement.step();
                if (result == SQLITE_ROW) {
                    permissions.push_back(Permission{
                        statement.column_int64(0),
                        statement.column_text(1),
                        statement.column_text(2)
                    });
                    continue;
                }
                if (result == SQLITE_DONE) {
                    break;
                }
                throw RbacRepositoryError(
                    sqlite_error(handle, "Listing RBAC permissions", result)
                );
            }
            return permissions;
        }
    );
}

std::vector<Role> RbacRepository::roles_for_user(
    std::int64_t user_id
) {
    if (user_id <= 0) {
        return {};
    }
    return database_.with_locked_handle(
        [user_id](sqlite3* handle) {
            return roles_for_user_locked(handle, user_id);
        }
    );
}

std::vector<std::string>
RbacRepository::permission_names_for_user(
    std::int64_t user_id
) {
    if (user_id <= 0) {
        return {};
    }
    return database_.with_locked_handle(
        [user_id](sqlite3* handle) {
            Statement statement{
                handle,
                R"SQL(
SELECT DISTINCT p.name
FROM permissions AS p
JOIN role_permissions AS rp ON rp.permission_id = p.id
JOIN user_roles AS ur ON ur.role_id = rp.role_id
WHERE ur.user_id = ?1
ORDER BY p.name ASC;
)SQL"
            };
            statement.bind_int64(1, user_id);
            std::vector<std::string> names;
            while (true) {
                const int result = statement.step();
                if (result == SQLITE_ROW) {
                    names.push_back(statement.column_text(0));
                    continue;
                }
                if (result == SQLITE_DONE) {
                    break;
                }
                throw RbacRepositoryError(
                    sqlite_error(handle, "Listing user permissions", result)
                );
            }
            return names;
        }
    );
}

bool RbacRepository::has_permission(
    std::int64_t user_id,
    std::string_view permission_name
) {
    if (user_id <= 0 || permission_name.empty()) {
        return false;
    }
    return database_.with_locked_handle(
        [user_id, permission_name](sqlite3* handle) {
            Statement statement{
                handle,
                R"SQL(
SELECT 1
FROM user_roles AS ur
JOIN role_permissions AS rp ON rp.role_id = ur.role_id
JOIN permissions AS p ON p.id = rp.permission_id
WHERE ur.user_id = ?1 AND p.name = ?2
LIMIT 1;
)SQL"
            };
            statement.bind_int64(1, user_id);
            statement.bind_text(2, permission_name);
            const int result = statement.step();
            if (result == SQLITE_ROW) {
                return true;
            }
            if (result == SQLITE_DONE) {
                return false;
            }
            throw RbacRepositoryError(
                sqlite_error(handle, "Checking user permission", result)
            );
        }
    );
}

bool RbacRepository::has_role(
    std::int64_t user_id,
    std::string_view role_name
) {
    if (user_id <= 0 || role_name.empty()) {
        return false;
    }
    return database_.with_locked_handle(
        [user_id, role_name](sqlite3* handle) {
            Statement statement{
                handle,
                R"SQL(
SELECT 1
FROM user_roles AS ur
JOIN roles AS r ON r.id = ur.role_id
WHERE ur.user_id = ?1 AND r.name = ?2
LIMIT 1;
)SQL"
            };
            statement.bind_int64(1, user_id);
            statement.bind_text(2, role_name);
            const int result = statement.step();
            if (result == SQLITE_ROW) {
                return true;
            }
            if (result == SQLITE_DONE) {
                return false;
            }
            throw RbacRepositoryError(
                sqlite_error(handle, "Checking user role", result)
            );
        }
    );
}


bool RbacRepository::has_role(
    DatabaseTransaction& transaction,
    std::int64_t user_id,
    std::string_view role_name
) {
    if (user_id <= 0 || role_name.empty()) {
        return false;
    }
    if (!transaction.belongs_to(database_)) {
        throw std::invalid_argument(
            "RBAC transaction belongs to another database"
        );
    }
    Statement statement{
        transaction.handle(),
        R"SQL(
SELECT 1
FROM user_roles AS ur
JOIN roles AS r ON r.id = ur.role_id
WHERE ur.user_id = ?1 AND r.name = ?2
LIMIT 1;
)SQL"
    };
    statement.bind_int64(1, user_id);
    statement.bind_text(2, role_name);
    const int result = statement.step();
    if (result == SQLITE_ROW) {
        return true;
    }
    if (result == SQLITE_DONE) {
        return false;
    }
    throw RbacRepositoryError(
        sqlite_error(
            transaction.handle(),
            "Checking transactional user role",
            result
        )
    );
}

bool RbacRepository::role_exists(
    std::string_view role_name
) {
    if (role_name.empty()) {
        return false;
    }
    return database_.with_locked_handle(
        [role_name](sqlite3* handle) {
            try {
                static_cast<void>(require_role_id(handle, role_name));
                return true;
            } catch (const RbacRoleNotFoundError&) {
                return false;
            }
        }
    );
}

std::int64_t RbacRepository::count_enabled_users_with_role(
    std::string_view role_name
) {
    return database_.with_locked_handle(
        [role_name](sqlite3* handle) {
            Statement statement{
                handle,
                R"SQL(
SELECT COUNT(DISTINCT u.id)
FROM users AS u
JOIN user_roles AS ur ON ur.user_id = u.id
JOIN roles AS r ON r.id = ur.role_id
WHERE u.enabled = 1 AND r.name = ?1;
)SQL"
            };
            statement.bind_text(1, role_name);
            const int result = statement.step();
            if (result != SQLITE_ROW) {
                throw RbacRepositoryError(
                    sqlite_error(handle, "Counting enabled role members", result)
                );
            }
            return statement.column_int64(0);
        }
    );
}


std::int64_t RbacRepository::count_enabled_users_with_role(
    DatabaseTransaction& transaction,
    std::string_view role_name
) {
    if (!transaction.belongs_to(database_)) {
        throw std::invalid_argument(
            "RBAC transaction belongs to another database"
        );
    }
    Statement statement{
        transaction.handle(),
        R"SQL(
SELECT COUNT(DISTINCT u.id)
FROM users AS u
JOIN user_roles AS ur ON ur.user_id = u.id
JOIN roles AS r ON r.id = ur.role_id
WHERE u.enabled = 1 AND r.name = ?1;
)SQL"
    };
    statement.bind_text(1, role_name);
    const int result = statement.step();
    if (result != SQLITE_ROW) {
        throw RbacRepositoryError(
            sqlite_error(
                transaction.handle(),
                "Counting transactional role members",
                result
            )
        );
    }
    return statement.column_int64(0);
}

bool RbacRepository::assign_role(
    std::int64_t user_id,
    std::string_view role_name,
    std::optional<std::int64_t> assigned_by
) {
    return database_.with_locked_handle(
        [user_id, role_name, assigned_by](sqlite3* handle) {
            return assign_role_locked(
                handle, user_id, role_name, assigned_by
            );
        }
    );
}

bool RbacRepository::assign_role(
    DatabaseTransaction& transaction,
    std::int64_t user_id,
    std::string_view role_name,
    std::optional<std::int64_t> assigned_by
) {
    if (!transaction.belongs_to(database_)) {
        throw std::invalid_argument(
            "RBAC transaction belongs to another database"
        );
    }
    return assign_role_locked(
        transaction.handle(), user_id, role_name, assigned_by
    );
}

bool RbacRepository::revoke_role(
    std::int64_t user_id,
    std::string_view role_name
) {
    return database_.with_locked_handle(
        [user_id, role_name](sqlite3* handle) {
            return revoke_role_locked(handle, user_id, role_name);
        }
    );
}

bool RbacRepository::revoke_role(
    DatabaseTransaction& transaction,
    std::int64_t user_id,
    std::string_view role_name
) {
    if (!transaction.belongs_to(database_)) {
        throw std::invalid_argument(
            "RBAC transaction belongs to another database"
        );
    }
    return revoke_role_locked(
        transaction.handle(), user_id, role_name
    );
}

}  // namespace secure
