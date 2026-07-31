#include "secure/database/migration.hpp"

#include "secure/database/database.hpp"

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

        database_.execute(
            "BEGIN IMMEDIATE;"
        );

        try {
            database_.execute(
                migration.sql
            );

            database_.execute(
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

            database_.execute(
                "COMMIT;"
            );
        } catch (...) {
            try {
                database_.execute(
                    "ROLLBACK;"
                );
            } catch (...) {
                /*
                 * 保留最初的迁移异常。
                 */
            }

            throw;
        }
    }
}

}  // namespace secure
