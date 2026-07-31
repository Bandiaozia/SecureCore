#include "secure/repository/user_repository.hpp"

#include "secure/database/database.hpp"

#include <cstdint>
#include <memory>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

#include <sqlite3.h>

namespace secure {

namespace {

std::string make_sqlite_error(
    sqlite3* handle,
    std::string_view operation,
    int result
) {
    std::ostringstream message;

    message
        << operation
        << " failed with SQLite code "
        << result
        << ": "
        << sqlite3_errmsg(handle);

    return message.str();
}

class Statement final {
public:
    Statement(
        sqlite3* handle,
        std::string_view sql
    )
        : handle_(handle) {
        const std::string sql_text(sql);

        const int result =
            sqlite3_prepare_v2(
                handle_,
                sql_text.c_str(),
                static_cast<int>(
                    sql_text.size()
                ),
                &statement_,
                nullptr
            );

        if (result != SQLITE_OK) {
            throw UserRepositoryError(
                make_sqlite_error(
                    handle_,
                    "Preparing user query",
                    result
                )
            );
        }
    }

    ~Statement() {
        if (statement_ != nullptr) {
            sqlite3_finalize(statement_);
            statement_ = nullptr;
        }
    }

    Statement(const Statement&) = delete;

    Statement& operator=(
        const Statement&
    ) = delete;

    void bind_int64(
        int index,
        std::int64_t value
    ) {
        const int result =
            sqlite3_bind_int64(
                statement_,
                index,
                value
            );

        check_bind_result(result);
    }

    void bind_text(
        int index,
        std::string_view value
    ) {
        const int result =
            sqlite3_bind_text(
                statement_,
                index,
                value.data(),
                static_cast<int>(
                    value.size()
                ),
                SQLITE_TRANSIENT
            );

        check_bind_result(result);
    }

    int step() {
        return sqlite3_step(statement_);
    }

    [[nodiscard]]
    std::int64_t column_int64(
        int index
    ) const {
        return sqlite3_column_int64(
            statement_,
            index
        );
    }

    [[nodiscard]]
    bool column_bool(
        int index
    ) const {
        return (
            sqlite3_column_int(
                statement_,
                index
            ) != 0
        );
    }

    [[nodiscard]]
    std::string column_text(
        int index
    ) const {
        const auto* raw_text =
            sqlite3_column_text(
                statement_,
                index
            );

        if (raw_text == nullptr) {
            return {};
        }

        const int byte_count =
            sqlite3_column_bytes(
                statement_,
                index
            );

        return {
            reinterpret_cast<
                const char*
            >(raw_text),
            static_cast<std::size_t>(
                byte_count
            )
        };
    }

private:
    void check_bind_result(
        int result
    ) {
        if (result != SQLITE_OK) {
            throw UserRepositoryError(
                make_sqlite_error(
                    handle_,
                    "Binding user query value",
                    result
                )
            );
        }
    }

    sqlite3* handle_{nullptr};

    sqlite3_stmt* statement_{nullptr};
};

User read_user(
    const Statement& statement
) {
    User user;

    user.id =
        statement.column_int64(0);

    user.username =
        statement.column_text(1);

    user.email =
        statement.column_text(2);

    user.password_hash =
        statement.column_text(3);

    user.role =
        statement.column_text(4);

    user.enabled =
        statement.column_bool(5);

    user.created_at =
        statement.column_text(6);

    user.updated_at =
        statement.column_text(7);

    return user;
}

std::optional<User>
read_optional_user(
    sqlite3* handle,
    Statement& statement
) {
    const int result = statement.step();

    if (result == SQLITE_ROW) {
        return read_user(statement);
    }

    if (result == SQLITE_DONE) {
        return std::nullopt;
    }

    throw UserRepositoryError(
        make_sqlite_error(
            handle,
            "Reading user query",
            result
        )
    );
}

std::optional<User>
find_by_id_locked(
    sqlite3* handle,
    std::int64_t user_id
) {
    Statement statement{
        handle,
        R"SQL(
SELECT
    id,
    username,
    email,
    password_hash,
    role,
    enabled,
    created_at,
    updated_at
FROM users
WHERE id = ?1
LIMIT 1;
)SQL"
    };

    statement.bind_int64(
        1,
        user_id
    );

    return read_optional_user(
        handle,
        statement
    );
}

}  // namespace

UserRepository::UserRepository(
    Database& database
)
    : database_(database) {
}

User UserRepository::create(
    const CreateUser& input
) {
    if (
        input.username.empty() ||
        input.email.empty() ||
        input.password_hash.empty()
    ) {
        throw std::invalid_argument(
            "User fields must not be empty"
        );
    }

    if (
        input.role != "user" &&
        input.role != "admin"
    ) {
        throw std::invalid_argument(
            "User role must be user or admin"
        );
    }

    return database_.with_locked_handle(
        [&input](
            sqlite3* handle
        ) -> User {
            Statement insert{
                handle,
                R"SQL(
INSERT INTO users (
    username,
    email,
    password_hash,
    role
)
VALUES (
    ?1,
    ?2,
    ?3,
    ?4
);
)SQL"
            };

            insert.bind_text(
                1,
                input.username
            );

            insert.bind_text(
                2,
                input.email
            );

            insert.bind_text(
                3,
                input.password_hash
            );

            insert.bind_text(
                4,
                input.role
            );

            const int result =
                insert.step();

            if (result != SQLITE_DONE) {
                const int extended_result =
                    sqlite3_extended_errcode(
                        handle
                    );

                if (
                    extended_result ==
                        SQLITE_CONSTRAINT_UNIQUE ||
                    extended_result ==
                        SQLITE_CONSTRAINT_PRIMARYKEY
                ) {
                    throw DuplicateUserError(
                        "Username or email "
                        "already exists"
                    );
                }

                throw UserRepositoryError(
                    make_sqlite_error(
                        handle,
                        "Creating user",
                        extended_result
                    )
                );
            }

            const std::int64_t user_id =
                sqlite3_last_insert_rowid(
                    handle
                );

            std::optional<User> user =
                find_by_id_locked(
                    handle,
                    user_id
                );

            if (!user.has_value()) {
                throw UserRepositoryError(
                    "Created user could not "
                    "be read back"
                );
            }

            return std::move(*user);
        }
    );
}

std::optional<User>
UserRepository::find_by_id(
    std::int64_t user_id
) {
    if (user_id <= 0) {
        return std::nullopt;
    }

    return database_.with_locked_handle(
        [user_id](
            sqlite3* handle
        ) {
            return find_by_id_locked(
                handle,
                user_id
            );
        }
    );
}

std::optional<User>
UserRepository::find_by_username(
    std::string_view username
) {
    return database_.with_locked_handle(
        [username](
            sqlite3* handle
        ) -> std::optional<User> {
            Statement statement{
                handle,
                R"SQL(
SELECT
    id,
    username,
    email,
    password_hash,
    role,
    enabled,
    created_at,
    updated_at
FROM users
WHERE username = ?1
LIMIT 1;
)SQL"
            };

            statement.bind_text(
                1,
                username
            );

            return read_optional_user(
                handle,
                statement
            );
        }
    );
}

std::optional<User>
UserRepository::find_by_email(
    std::string_view email
) {
    return database_.with_locked_handle(
        [email](
            sqlite3* handle
        ) -> std::optional<User> {
            Statement statement{
                handle,
                R"SQL(
SELECT
    id,
    username,
    email,
    password_hash,
    role,
    enabled,
    created_at,
    updated_at
FROM users
WHERE email = ?1
LIMIT 1;
)SQL"
            };

            statement.bind_text(
                1,
                email
            );

            return read_optional_user(
                handle,
                statement
            );
        }
    );
}

std::optional<User>
UserRepository::find_by_login(
    std::string_view login
) {
    return database_.with_locked_handle(
        [login](
            sqlite3* handle
        ) -> std::optional<User> {
            Statement statement{
                handle,
                R"SQL(
SELECT
    id,
    username,
    email,
    password_hash,
    role,
    enabled,
    created_at,
    updated_at
FROM users
WHERE
    username = ?1
    OR email = ?1
LIMIT 1;
)SQL"
            };

            statement.bind_text(
                1,
                login
            );

            return read_optional_user(
                handle,
                statement
            );
        }
    );
}


std::vector<User> UserRepository::list(
    std::int64_t limit,
    std::int64_t offset
) {
    if (
        limit <= 0 ||
        limit > 100
    ) {
        throw std::invalid_argument(
            "User list limit must be "
            "between 1 and 100"
        );
    }

    if (offset < 0) {
        throw std::invalid_argument(
            "User list offset must not "
            "be negative"
        );
    }

    return database_.with_locked_handle(
        [
            limit,
            offset
        ](
            sqlite3* handle
        ) {
            Statement statement{
                handle,
                R"SQL(
SELECT
    id,
    username,
    email,
    password_hash,
    role,
    enabled,
    created_at,
    updated_at
FROM users
ORDER BY id ASC
LIMIT ?1
OFFSET ?2;
)SQL"
            };

            statement.bind_int64(
                1,
                limit
            );

            statement.bind_int64(
                2,
                offset
            );

            std::vector<User> users;

            while (true) {
                const int result =
                    statement.step();

                if (result == SQLITE_ROW) {
                    users.push_back(
                        read_user(statement)
                    );

                    continue;
                }

                if (result == SQLITE_DONE) {
                    break;
                }

                throw UserRepositoryError(
                    make_sqlite_error(
                        handle,
                        "Listing users",
                        result
                    )
                );
            }

            return users;
        }
    );
}

std::int64_t UserRepository::count() {
    return database_.query_int64(
        "SELECT COUNT(*) FROM users;"
    );
}

std::int64_t
UserRepository::count_enabled_admins() {
    return database_.query_int64(
        R"SQL(
SELECT COUNT(*)
FROM users
WHERE
    role = 'admin'
    AND enabled = 1;
)SQL"
    );
}

bool UserRepository::set_role(
    std::int64_t user_id,
    std::string_view role
) {
    if (user_id <= 0) {
        return false;
    }

    if (
        role != "user" &&
        role != "admin"
    ) {
        throw std::invalid_argument(
            "User role must be user or admin"
        );
    }

    return database_.with_locked_handle(
        [
            user_id,
            role
        ](
            sqlite3* handle
        ) {
            Statement statement{
                handle,
                R"SQL(
UPDATE users
SET
    role = ?1,
    updated_at = strftime(
        '%Y-%m-%dT%H:%M:%fZ',
        'now'
    )
WHERE id = ?2;
)SQL"
            };

            statement.bind_text(
                1,
                role
            );

            statement.bind_int64(
                2,
                user_id
            );

            const int result =
                statement.step();

            if (result != SQLITE_DONE) {
                throw UserRepositoryError(
                    make_sqlite_error(
                        handle,
                        "Updating user role",
                        result
                    )
                );
            }

            return (
                sqlite3_changes(handle) > 0
            );
        }
    );
}

bool UserRepository::set_enabled(
    std::int64_t user_id,
    bool enabled
) {
    if (user_id <= 0) {
        return false;
    }

    return database_.with_locked_handle(
        [
            user_id,
            enabled
        ](
            sqlite3* handle
        ) {
            Statement statement{
                handle,
                R"SQL(
UPDATE users
SET
    enabled = ?1,
    updated_at = strftime(
        '%Y-%m-%dT%H:%M:%fZ',
        'now'
    )
WHERE id = ?2;
)SQL"
            };

            statement.bind_int64(
                1,
                enabled ? 1 : 0
            );

            statement.bind_int64(
                2,
                user_id
            );

            const int result =
                statement.step();

            if (result != SQLITE_DONE) {
                throw UserRepositoryError(
                    make_sqlite_error(
                        handle,
                        "Updating user status",
                        result
                    )
                );
            }

            return (
                sqlite3_changes(handle) > 0
            );
        }
    );
}

}  // namespace secure
