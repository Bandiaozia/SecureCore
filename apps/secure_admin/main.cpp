#include "secure/config/server_config.hpp"
#include "secure/database/database.hpp"
#include "secure/database/migration.hpp"
#include "secure/model/user.hpp"
#include "secure/repository/auth_session_repository.hpp"
#include "secure/repository/user_repository.hpp"

#include <cstdint>
#include <cstdlib>
#include <exception>
#include <iostream>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>

namespace {

void print_usage(
    std::string_view program
) {
    std::cerr
        << "Usage:\n  "
        << program
        << " <config-file> "
        << "<promote|demote|enable|disable> "
        << "<username-or-email>\n";
}

void print_user(
    const secure::User& user,
    std::int64_t revoked_sessions,
    bool changed
) {
    std::cout
        << "Operation completed.\n"
        << "changed="
        << (changed ? "true" : "false")
        << '\n'
        << "id=" << user.id << '\n'
        << "username=" << user.username << '\n'
        << "email=" << user.email << '\n'
        << "role=" << user.role << '\n'
        << "enabled="
        << (user.enabled ? "true" : "false")
        << '\n'
        << "revoked_sessions="
        << revoked_sessions
        << '\n';
}

bool is_supported_command(
    std::string_view command
) {
    return (
        command == "promote" ||
        command == "demote" ||
        command == "enable" ||
        command == "disable"
    );
}

}  // namespace

int main(
    int argc,
    char* argv[]
) {
    if (argc != 4) {
        print_usage(argv[0]);

        return EXIT_FAILURE;
    }

    const std::string config_path{
        argv[1]
    };

    const std::string command{
        argv[2]
    };

    const std::string identifier{
        argv[3]
    };

    if (!is_supported_command(command)) {
        std::cerr
            << "Unsupported command: "
            << command
            << '\n';

        print_usage(argv[0]);

        return EXIT_FAILURE;
    }

    try {
        const secure::ServerConfig config =
            secure::ServerConfig::
                load_from_file(
                    config_path
                );

        config.validate_for_admin();

        secure::Database database(
            config.database_path()
        );

        secure::MigrationRunner migration_runner(
            database
        );

        migration_runner.apply();

        secure::UserRepository user_repository(
            database
        );

        secure::AuthSessionRepository
            auth_session_repository(
                database
            );

        const std::optional<secure::User>
            user =
                user_repository.find_by_login(
                    identifier
                );

        if (!user.has_value()) {
            throw std::runtime_error(
                "User was not found: " +
                identifier
            );
        }

        bool changed = false;

        if (command == "promote") {
            if (user->role != "admin") {
                if (
                    !user_repository.set_role(
                        user->id,
                        "admin"
                    )
                ) {
                    throw std::runtime_error(
                        "Failed to promote user"
                    );
                }

                changed = true;
            }
        } else if (command == "demote") {
            if (user->role == "admin") {
                if (
                    user->enabled &&
                    user_repository
                        .count_enabled_admins() <= 1
                ) {
                    throw std::runtime_error(
                        "Refusing to demote the "
                        "last enabled administrator"
                    );
                }

                if (
                    !user_repository.set_role(
                        user->id,
                        "user"
                    )
                ) {
                    throw std::runtime_error(
                        "Failed to demote user"
                    );
                }

                changed = true;
            }
        } else if (command == "enable") {
            if (!user->enabled) {
                if (
                    !user_repository.set_enabled(
                        user->id,
                        true
                    )
                ) {
                    throw std::runtime_error(
                        "Failed to enable user"
                    );
                }

                changed = true;
            }
        } else if (command == "disable") {
            if (user->enabled) {
                if (
                    user->role == "admin" &&
                    user_repository
                        .count_enabled_admins() <= 1
                ) {
                    throw std::runtime_error(
                        "Refusing to disable the "
                        "last enabled administrator"
                    );
                }

                if (
                    !user_repository.set_enabled(
                        user->id,
                        false
                    )
                ) {
                    throw std::runtime_error(
                        "Failed to disable user"
                    );
                }

                changed = true;
            }
        }

        std::int64_t revoked_sessions = 0;

        if (changed) {
            revoked_sessions =
                auth_session_repository
                    .revoke_all_for_user(
                        user->id
                    );
        }

        const std::optional<secure::User>
            updated_user =
                user_repository.find_by_id(
                    user->id
                );

        if (!updated_user.has_value()) {
            throw std::runtime_error(
                "Updated user could not "
                "be read back"
            );
        }

        print_user(
            *updated_user,
            revoked_sessions,
            changed
        );

        return EXIT_SUCCESS;
    } catch (
        const std::exception& error
    ) {
        std::cerr
            << "SecureCore admin operation "
            << "failed: "
            << error.what()
            << '\n';

        return EXIT_FAILURE;
    }
}
