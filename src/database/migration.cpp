#include "secure/database/migration.hpp"

#include "secure/database/database.hpp"
#include "secure/database/transaction.hpp"

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace secure {

namespace {

struct Migration final {
    std::int64_t version;

    std::string_view name;

    std::string_view sql;
};

const std::vector<Migration>&
migrations() {
    static const std::vector<Migration>
        migration_list{
            {
                1,
                "create_users",
                R"SQL(
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,

    username TEXT NOT NULL
        COLLATE NOCASE
        UNIQUE,

    email TEXT NOT NULL
        COLLATE NOCASE
        UNIQUE,

    password_hash TEXT NOT NULL,

    role TEXT NOT NULL
        DEFAULT 'user'
        CHECK (
            role IN ('user', 'admin')
        ),

    enabled INTEGER NOT NULL
        DEFAULT 1
        CHECK (
            enabled IN (0, 1)
        ),

    created_at TEXT NOT NULL
        DEFAULT (
            strftime(
                '%Y-%m-%dT%H:%M:%fZ',
                'now'
            )
        ),

    updated_at TEXT NOT NULL
        DEFAULT (
            strftime(
                '%Y-%m-%dT%H:%M:%fZ',
                'now'
            )
        )
);
)SQL"
            },
            {
                2,
                "create_auth_sessions",
                R"SQL(
CREATE TABLE IF NOT EXISTS auth_sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,

    user_id INTEGER NOT NULL,

    access_token_hash TEXT NOT NULL
        UNIQUE,

    refresh_token_hash TEXT NOT NULL
        UNIQUE,

    access_expires_at INTEGER NOT NULL,

    refresh_expires_at INTEGER NOT NULL,

    revoked INTEGER NOT NULL
        DEFAULT 0
        CHECK (
            revoked IN (0, 1)
        ),

    created_at TEXT NOT NULL
        DEFAULT (
            strftime(
                '%Y-%m-%dT%H:%M:%fZ',
                'now'
            )
        ),

    revoked_at TEXT,

    FOREIGN KEY (user_id)
        REFERENCES users(id)
        ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS
    idx_auth_sessions_user_id
ON auth_sessions(user_id);

CREATE INDEX IF NOT EXISTS
    idx_auth_sessions_refresh_expires_at
ON auth_sessions(refresh_expires_at);
)SQL"
            }
        };

    return migration_list;
}

}  // namespace

MigrationRunner::MigrationRunner(
    Database& database
)
    : database_(database) {
}

void MigrationRunner::apply() {
    database_.execute(
        R"SQL(
CREATE TABLE IF NOT EXISTS schema_migrations (
    version INTEGER PRIMARY KEY,

    name TEXT NOT NULL,

    applied_at TEXT NOT NULL
        DEFAULT (
            strftime(
                '%Y-%m-%dT%H:%M:%fZ',
                'now'
            )
        )
);
)SQL"
    );

    const std::int64_t current_version =
        database_.query_int64(
            R"SQL(
SELECT COALESCE(
    MAX(version),
    0
)
FROM schema_migrations;
)SQL"
        );

    for (
        const Migration& migration :
        migrations()
    ) {
        if (
            migration.version <=
            current_version
        ) {
            continue;
        }

        auto transaction =
            database_.begin_transaction();

        transaction.execute(
            migration.sql
        );

        transaction.execute(
            "INSERT INTO "
            "schema_migrations "
            "(version, name) VALUES (" +
            std::to_string(
                migration.version
            ) +
            ", '" +
            std::string(
                migration.name
            ) +
            "');"
        );

        transaction.commit();
    }
}

}  // namespace secure
