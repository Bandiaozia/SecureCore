#include "secure/config/server_config.hpp"
#include "secure/database/database.hpp"
#include "secure/database/migration.hpp"
#include "secure/database/transaction.hpp"
#include "secure/model/audit_event.hpp"
#include "secure/model/rbac.hpp"
#include "secure/model/user.hpp"
#include "secure/repository/audit_repository.hpp"
#include "secure/repository/auth_session_repository.hpp"
#include "secure/repository/rbac_repository.hpp"
#include "secure/repository/user_repository.hpp"

#include <cstdint>
#include <cstdlib>
#include <exception>
#include <iostream>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace {

void print_usage(std::string_view program) {
    std::cerr
        << "Usage:\n"
        << "  " << program
        << " <config> <promote|demote|enable|disable|list-roles> <user>\n"
        << "  " << program
        << " <config> <assign-role|revoke-role> <user> <role>\n"
        << "  " << program
        << " <config> <roles|permissions>\n";
}

std::string join_role_names(
    const std::vector<secure::Role>& roles
) {
    std::string result;
    for (const auto& role : roles) {
        if (!result.empty()) {
            result += ',';
        }
        result += role.name;
    }
    return result;
}

void print_user(
    const secure::User& user,
    const std::vector<secure::Role>& roles,
    std::int64_t revoked_sessions,
    bool changed
) {
    std::cout
        << "Operation completed.\n"
        << "changed=" << (changed ? "true" : "false") << '\n'
        << "id=" << user.id << '\n'
        << "username=" << user.username << '\n'
        << "email=" << user.email << '\n'
        << "role=" << user.role << '\n'
        << "roles=" << join_role_names(roles) << '\n'
        << "enabled=" << (user.enabled ? "true" : "false") << '\n'
        << "revoked_sessions=" << revoked_sessions << '\n';
}

void write_audit(
    secure::AuditRepository& repository,
    std::string event_type,
    std::int64_t target_id,
    std::string metadata
) noexcept {
    try {
        static_cast<void>(repository.create(
            secure::CreateAuditEvent{
                std::nullopt,
                std::move(event_type),
                "success",
                "user",
                target_id,
                "secure-admin",
                "local",
                "secure-admin",
                std::move(metadata)
            }
        ));
    } catch (const std::exception& error) {
        std::cerr
            << "Warning: operation completed, but the audit event "
            << "could not be stored: " << error.what() << '\n';
    }
}

}  // namespace

int main(int argc, char* argv[]) {
    if (argc < 3 || argc > 5) {
        print_usage(argv[0]);
        return EXIT_FAILURE;
    }

    const std::string config_path{argv[1]};
    const std::string command{argv[2]};

    try {
        const secure::ServerConfig config =
            secure::ServerConfig::load_from_file(config_path);
        config.validate_for_admin();

        secure::Database database(
            config.database_path(),
            config.database_pool_size()
        );
        secure::MigrationRunner migration_runner(database);
        migration_runner.apply();

        secure::UserRepository user_repository(database);
        secure::AuthSessionRepository session_repository(database);
        secure::RbacRepository rbac_repository(database);
        secure::AuditRepository audit_repository(database);

        if (command == "roles") {
            if (argc != 3) {
                throw std::runtime_error("roles does not accept a user argument");
            }
            for (const auto& role : rbac_repository.list_roles()) {
                std::cout << role.name << '\t' << role.description << '\n';
            }
            return EXIT_SUCCESS;
        }

        if (command == "permissions") {
            if (argc != 3) {
                throw std::runtime_error("permissions does not accept a user argument");
            }
            for (const auto& permission : rbac_repository.list_permissions()) {
                std::cout << permission.name << '\t'
                          << permission.description << '\n';
            }
            return EXIT_SUCCESS;
        }

        const bool role_command =
            command == "assign-role" || command == "revoke-role";
        if ((role_command && argc != 5) || (!role_command && argc != 4)) {
            print_usage(argv[0]);
            return EXIT_FAILURE;
        }

        const std::string identifier{argv[3]};
        const std::optional<secure::User> found =
            user_repository.find_by_login(identifier);
        if (!found.has_value()) {
            throw std::runtime_error("User was not found: " + identifier);
        }

        if (command == "list-roles") {
            const auto roles = rbac_repository.roles_for_user(found->id);
            print_user(*found, roles, 0, false);
            return EXIT_SUCCESS;
        }

        std::string role_name;
        std::string audit_command = command;
        bool assigning = false;
        bool revoking = false;

        if (command == "promote") {
            role_name = "super_admin";
            assigning = true;
        } else if (command == "demote") {
            role_name = "super_admin";
            revoking = true;
        } else if (command == "assign-role") {
            role_name = argv[4];
            assigning = true;
        } else if (command == "revoke-role") {
            role_name = argv[4];
            revoking = true;
        } else if (command != "enable" && command != "disable") {
            throw std::runtime_error("Unsupported command: " + command);
        }

        auto transaction = database.begin_transaction();
        const std::optional<secure::User> user =
            user_repository.find_by_id(transaction, found->id);
        if (!user.has_value()) {
            throw std::runtime_error("User disappeared during operation");
        }

        bool changed = false;
        std::int64_t revoked_sessions = 0;

        if (assigning) {
            changed = rbac_repository.assign_role(
                transaction,
                user->id,
                role_name,
                std::nullopt
            );
        } else if (revoking) {
            if (role_name == "user") {
                throw std::runtime_error("The base user role cannot be removed");
            }
            if (
                role_name == "super_admin" &&
                user->enabled &&
                rbac_repository.has_role(
                    transaction, user->id, role_name
                ) &&
                rbac_repository.count_enabled_users_with_role(
                    transaction, role_name
                ) <= 1
            ) {
                throw std::runtime_error(
                    "Refusing to remove the last enabled super administrator"
                );
            }
            changed = rbac_repository.revoke_role(
                transaction, user->id, role_name
            );
        } else if (command == "enable") {
            if (!user->enabled) {
                changed = user_repository.set_enabled(
                    transaction, user->id, true
                );
            }
        } else if (command == "disable") {
            if (user->enabled) {
                if (
                    rbac_repository.has_role(
                        transaction, user->id, "super_admin"
                    ) &&
                    rbac_repository.count_enabled_users_with_role(
                        transaction, "super_admin"
                    ) <= 1
                ) {
                    throw std::runtime_error(
                        "Refusing to disable the last enabled super administrator"
                    );
                }
                changed = user_repository.set_enabled(
                    transaction, user->id, false
                );
                if (changed) {
                    revoked_sessions = session_repository.revoke_all_for_user(
                        transaction, user->id
                    );
                }
            }
        }

        const std::optional<secure::User> updated =
            user_repository.find_by_id(transaction, user->id);
        if (!updated.has_value()) {
            throw std::runtime_error("Updated user could not be read back");
        }
        transaction.commit();

        const auto roles = rbac_repository.roles_for_user(user->id);
        std::string metadata =
            std::string("{\"changed\":") +
            (changed ? "true" : "false") +
            ",\"revoked_sessions\":" +
            std::to_string(revoked_sessions);
        if (!role_name.empty()) {
            metadata += ",\"role\":\"" + role_name + "\"";
        }
        metadata += "}";

        write_audit(
            audit_repository,
            "admin.cli." + audit_command,
            updated->id,
            std::move(metadata)
        );

        print_user(*updated, roles, revoked_sessions, changed);
        return EXIT_SUCCESS;
    } catch (const std::exception& error) {
        std::cerr
            << "SecureCore admin operation failed: "
            << error.what() << '\n';
        return EXIT_FAILURE;
    }
}
