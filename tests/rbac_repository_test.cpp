#include "secure/database/database.hpp"
#include "secure/database/migration.hpp"
#include "secure/database/transaction.hpp"
#include "secure/repository/rbac_repository.hpp"
#include "secure/repository/user_repository.hpp"

#include <chrono>
#include <filesystem>
#include <iostream>
#include <stdexcept>
#include <string>

namespace {

void require(bool condition, const char* message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

std::filesystem::path temporary_database_path(
    const char* suffix
) {
    return std::filesystem::temp_directory_path() /
        (std::string("securecore-rbac-") + suffix + "-" +
         std::to_string(
             std::chrono::steady_clock::now()
                 .time_since_epoch()
                 .count()
         ) + ".db");
}

void test_repository_and_default_role() {
    const auto path = temporary_database_path("repository");
    std::filesystem::remove(path);

    {
        secure::Database database(path, 2);
        secure::MigrationRunner migrations(database);
        migrations.apply();

        require(
            database.query_int64(
                "SELECT MAX(version) FROM schema_migrations;"
            ) == 5,
            "schema version must be 5"
        );

        secure::UserRepository users(database);
        secure::RbacRepository rbac(database);

        const auto roles = rbac.list_roles();
        const auto permissions = rbac.list_permissions();
        require(roles.size() == 5, "five built-in roles expected");
        require(permissions.size() == 8, "eight permissions expected");

        const secure::User alice = users.create(
            secure::CreateUser{
                "alice",
                "alice@example.com",
                "not-a-real-password-hash",
                "user"
            }
        );

        require(
            rbac.has_role(alice.id, "user"),
            "new users must receive the base role"
        );
        require(
            !rbac.has_permission(alice.id, "users.read"),
            "base users must not receive admin permissions"
        );

        require(
            rbac.assign_role(alice.id, "support"),
            "support assignment must change state"
        );
        require(
            !rbac.assign_role(alice.id, "support"),
            "duplicate role assignment must be idempotent"
        );
        require(
            rbac.has_permission(alice.id, "users.read"),
            "support must read users"
        );
        require(
            rbac.has_permission(alice.id, "users.enable"),
            "support must enable users"
        );
        require(
            !rbac.has_permission(alice.id, "users.disable"),
            "support must not disable users"
        );

        {
            auto transaction = database.begin_transaction();
            require(
                rbac.revoke_role(transaction, alice.id, "support"),
                "transactional revoke must change state"
            );
            // Destructor rolls back.
        }
        require(
            rbac.has_role(alice.id, "support"),
            "rolled-back role revoke must not persist"
        );

        require(
            rbac.assign_role(alice.id, "super_admin"),
            "super-admin assignment must change state"
        );
        require(
            rbac.count_enabled_users_with_role("super_admin") == 1,
            "one enabled super administrator expected"
        );
        require(
            rbac.has_permission(alice.id, "roles.manage"),
            "super administrators must manage roles"
        );

        const auto updated = users.find_by_id(alice.id);
        require(updated.has_value(), "updated user must exist");
        require(
            updated->role == "admin",
            "legacy role alias must remain compatible"
        );

        require(
            rbac.revoke_role(alice.id, "support"),
            "support revoke must persist"
        );
        require(
            !rbac.has_role(alice.id, "support"),
            "support role must be removed"
        );

        bool role_error = false;
        try {
            static_cast<void>(
                rbac.assign_role(alice.id, "does_not_exist")
            );
        } catch (const secure::RbacRoleNotFoundError&) {
            role_error = true;
        }
        require(role_error, "unknown roles must be rejected");
    }

    std::filesystem::remove(path);
}

void test_legacy_admin_migration() {
    const auto path = temporary_database_path("legacy");
    std::filesystem::remove(path);

    {
        secure::Database database(path, 1);
        database.execute(R"SQL(
CREATE TABLE schema_migrations (
    version INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    applied_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
INSERT INTO schema_migrations(version, name) VALUES
    (1, 'create_users'),
    (2, 'create_auth_sessions'),
    (3, 'create_audit_events'),
    (4, 'add_refresh_token_families');

CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL COLLATE NOCASE UNIQUE,
    email TEXT NOT NULL COLLATE NOCASE UNIQUE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'user'
        CHECK (role IN ('user', 'admin')),
    enabled INTEGER NOT NULL DEFAULT 1
        CHECK (enabled IN (0, 1)),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO users(username, email, password_hash, role)
VALUES ('legacyadmin', 'legacy@example.com', 'hash', 'admin');
)SQL");

        secure::MigrationRunner migrations(database);
        migrations.apply();
        secure::RbacRepository rbac(database);

        require(
            rbac.has_role(1, "super_admin"),
            "legacy administrators must migrate to super_admin"
        );
        require(
            rbac.has_permission(1, "roles.manage"),
            "migrated administrators must retain full access"
        );
    }

    std::filesystem::remove(path);
}

}  // namespace

int main() {
    try {
        test_repository_and_default_role();
        test_legacy_admin_migration();
        std::cout << "RBAC repository tests passed.\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "RBAC repository test failed: "
                  << error.what() << '\n';
        return 1;
    }
}
