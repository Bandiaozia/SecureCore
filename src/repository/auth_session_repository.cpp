#include "secure/repository/auth_session_repository.hpp"

#include "secure/database/database.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>

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
            throw AuthSessionRepositoryError(
                make_sqlite_error(
                    handle_,
                    "Preparing auth session query",
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
        check_result(
            sqlite3_bind_int64(
                statement_,
                index,
                value
            ),
            "Binding integer value"
        );
    }

    void bind_text(
        int index,
        std::string_view value
    ) {
        check_result(
            sqlite3_bind_text(
                statement_,
                index,
                value.data(),
                static_cast<int>(
                    value.size()
                ),
                SQLITE_TRANSIENT
            ),
            "Binding text value"
        );
    }

    [[nodiscard]]
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
        const auto* value =
            sqlite3_column_text(
                statement_,
                index
            );

        if (value == nullptr) {
            return {};
        }

        const int size =
            sqlite3_column_bytes(
                statement_,
                index
            );

        return std::string(
            reinterpret_cast<
                const char*
            >(value),
            static_cast<std::size_t>(
                size
            )
        );
    }

    [[nodiscard]]
    std::optional<std::string>
    column_optional_text(
        int index
    ) const {
        if (
            sqlite3_column_type(
                statement_,
                index
            ) == SQLITE_NULL
        ) {
            return std::nullopt;
        }

        return column_text(index);
    }

private:
    void check_result(
        int result,
        std::string_view operation
    ) {
        if (result != SQLITE_OK) {
            throw AuthSessionRepositoryError(
                make_sqlite_error(
                    handle_,
                    operation,
                    result
                )
            );
        }
    }

    sqlite3* handle_{nullptr};

    sqlite3_stmt* statement_{nullptr};
};

AuthSession read_session(
    const Statement& statement
) {
    AuthSession session;

    session.id =
        statement.column_int64(0);

    session.user_id =
        statement.column_int64(1);

    session.access_token_hash =
        statement.column_text(2);

    session.refresh_token_hash =
        statement.column_text(3);

    session.access_expires_at =
        statement.column_int64(4);

    session.refresh_expires_at =
        statement.column_int64(5);

    session.revoked =
        statement.column_bool(6);

    session.created_at =
        statement.column_text(7);

    session.revoked_at =
        statement.column_optional_text(8);

    return session;
}

std::optional<AuthSession>
read_optional_session(
    sqlite3* handle,
    Statement& statement
) {
    const int result =
        statement.step();

    if (result == SQLITE_ROW) {
        return read_session(statement);
    }

    if (result == SQLITE_DONE) {
        return std::nullopt;
    }

    throw AuthSessionRepositoryError(
        make_sqlite_error(
            handle,
            "Reading auth session",
            result
        )
    );
}

std::optional<AuthSession>
find_by_id_locked(
    sqlite3* handle,
    std::int64_t session_id
) {
    Statement statement{
        handle,
        R"SQL(
SELECT
    id,
    user_id,
    access_token_hash,
    refresh_token_hash,
    access_expires_at,
    refresh_expires_at,
    revoked,
    created_at,
    revoked_at
FROM auth_sessions
WHERE id = ?1
LIMIT 1;
)SQL"
    };

    statement.bind_int64(
        1,
        session_id
    );

    return read_optional_session(
        handle,
        statement
    );
}

}  // namespace

AuthSessionRepository::
AuthSessionRepository(
    Database& database
)
    : database_(database) {
}

AuthSession AuthSessionRepository::create(
    const CreateAuthSession& input
) {
    if (
        input.user_id <= 0 ||
        input.access_token_hash.empty() ||
        input.refresh_token_hash.empty() ||
        input.access_expires_at <= 0 ||
        input.refresh_expires_at <=
            input.access_expires_at
    ) {
        throw std::invalid_argument(
            "Invalid authentication session"
        );
    }

    return database_.with_locked_handle(
        [&input](
            sqlite3* handle
        ) -> AuthSession {
            Statement statement{
                handle,
                R"SQL(
INSERT INTO auth_sessions (
    user_id,
    access_token_hash,
    refresh_token_hash,
    access_expires_at,
    refresh_expires_at
)
VALUES (
    ?1,
    ?2,
    ?3,
    ?4,
    ?5
);
)SQL"
            };

            statement.bind_int64(
                1,
                input.user_id
            );

            statement.bind_text(
                2,
                input.access_token_hash
            );

            statement.bind_text(
                3,
                input.refresh_token_hash
            );

            statement.bind_int64(
                4,
                input.access_expires_at
            );

            statement.bind_int64(
                5,
                input.refresh_expires_at
            );

            const int result =
                statement.step();

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
                    throw DuplicateTokenError(
                        "Authentication token "
                        "hash already exists"
                    );
                }

                throw AuthSessionRepositoryError(
                    make_sqlite_error(
                        handle,
                        "Creating auth session",
                        extended_result
                    )
                );
            }

            const std::int64_t session_id =
                sqlite3_last_insert_rowid(
                    handle
                );

            auto session =
                find_by_id_locked(
                    handle,
                    session_id
                );

            if (!session.has_value()) {
                throw AuthSessionRepositoryError(
                    "Created auth session "
                    "could not be read back"
                );
            }

            return std::move(*session);
        }
    );
}

std::optional<AuthSession>
AuthSessionRepository::
find_by_access_token_hash(
    std::string_view token_hash
) {
    if (token_hash.empty()) {
        return std::nullopt;
    }

    return database_.with_locked_handle(
        [token_hash](
            sqlite3* handle
        ) -> std::optional<AuthSession> {
            Statement statement{
                handle,
                R"SQL(
SELECT
    id,
    user_id,
    access_token_hash,
    refresh_token_hash,
    access_expires_at,
    refresh_expires_at,
    revoked,
    created_at,
    revoked_at
FROM auth_sessions
WHERE access_token_hash = ?1
LIMIT 1;
)SQL"
            };

            statement.bind_text(
                1,
                token_hash
            );

            return read_optional_session(
                handle,
                statement
            );
        }
    );
}

std::optional<AuthSession>
AuthSessionRepository::
find_by_refresh_token_hash(
    std::string_view token_hash
) {
    if (token_hash.empty()) {
        return std::nullopt;
    }

    return database_.with_locked_handle(
        [token_hash](
            sqlite3* handle
        ) -> std::optional<AuthSession> {
            Statement statement{
                handle,
                R"SQL(
SELECT
    id,
    user_id,
    access_token_hash,
    refresh_token_hash,
    access_expires_at,
    refresh_expires_at,
    revoked,
    created_at,
    revoked_at
FROM auth_sessions
WHERE refresh_token_hash = ?1
LIMIT 1;
)SQL"
            };

            statement.bind_text(
                1,
                token_hash
            );

            return read_optional_session(
                handle,
                statement
            );
        }
    );
}

bool AuthSessionRepository::revoke_by_id(
    std::int64_t session_id
) {
    if (session_id <= 0) {
        return false;
    }

    return database_.with_locked_handle(
        [session_id](
            sqlite3* handle
        ) {
            Statement statement{
                handle,
                R"SQL(
UPDATE auth_sessions
SET
    revoked = 1,
    revoked_at = strftime(
        '%Y-%m-%dT%H:%M:%fZ',
        'now'
    )
WHERE
    id = ?1
    AND revoked = 0;
)SQL"
            };

            statement.bind_int64(
                1,
                session_id
            );

            const int result =
                statement.step();

            if (result != SQLITE_DONE) {
                throw AuthSessionRepositoryError(
                    make_sqlite_error(
                        handle,
                        "Revoking auth session",
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

bool AuthSessionRepository::
revoke_by_refresh_token_hash(
    std::string_view token_hash
) {
    if (token_hash.empty()) {
        return false;
    }

    return database_.with_locked_handle(
        [token_hash](
            sqlite3* handle
        ) {
            Statement statement{
                handle,
                R"SQL(
UPDATE auth_sessions
SET
    revoked = 1,
    revoked_at = strftime(
        '%Y-%m-%dT%H:%M:%fZ',
        'now'
    )
WHERE
    refresh_token_hash = ?1
    AND revoked = 0;
)SQL"
            };

            statement.bind_text(
                1,
                token_hash
            );

            const int result =
                statement.step();

            if (result != SQLITE_DONE) {
                throw AuthSessionRepositoryError(
                    make_sqlite_error(
                        handle,
                        "Revoking refresh token",
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

std::int64_t
AuthSessionRepository::
revoke_all_for_user(
    std::int64_t user_id
) {
    if (user_id <= 0) {
        return 0;
    }

    return database_.with_locked_handle(
        [user_id](
            sqlite3* handle
        ) -> std::int64_t {
            Statement statement{
                handle,
                R"SQL(
UPDATE auth_sessions
SET
    revoked = 1,
    revoked_at = strftime(
        '%Y-%m-%dT%H:%M:%fZ',
        'now'
    )
WHERE
    user_id = ?1
    AND revoked = 0;
)SQL"
            };

            statement.bind_int64(
                1,
                user_id
            );

            const int result =
                statement.step();

            if (result != SQLITE_DONE) {
                throw AuthSessionRepositoryError(
                    make_sqlite_error(
                        handle,
                        "Revoking user sessions",
                        result
                    )
                );
            }

            return sqlite3_changes64(
                handle
            );
        }
    );
}

std::int64_t
AuthSessionRepository::delete_expired(
    std::int64_t current_time
) {
    return database_.with_locked_handle(
        [current_time](
            sqlite3* handle
        ) -> std::int64_t {
            Statement statement{
                handle,
                R"SQL(
DELETE FROM auth_sessions
WHERE refresh_expires_at <= ?1;
)SQL"
            };

            statement.bind_int64(
                1,
                current_time
            );

            const int result =
                statement.step();

            if (result != SQLITE_DONE) {
                throw AuthSessionRepositoryError(
                    make_sqlite_error(
                        handle,
                        "Deleting expired sessions",
                        result
                    )
                );
            }

            return sqlite3_changes64(
                handle
            );
        }
    );
}

}  // namespace secure
