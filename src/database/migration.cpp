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
            },
            {
                3,
                "create_audit_events",
                R"SQL(
CREATE TABLE IF NOT EXISTS audit_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,

    actor_user_id INTEGER,

    event_type TEXT NOT NULL,

    outcome TEXT NOT NULL
        CHECK (
            outcome IN ('success', 'failure')
        ),

    target_type TEXT NOT NULL
        DEFAULT '',

    target_id INTEGER,

    request_id TEXT NOT NULL
        DEFAULT '',

    client_ip TEXT NOT NULL
        DEFAULT '',

    user_agent TEXT NOT NULL
        DEFAULT '',

    metadata_json TEXT NOT NULL
        DEFAULT '{}'
        CHECK (
            json_valid(metadata_json)
        ),

    created_at TEXT NOT NULL
        DEFAULT (
            strftime(
                '%Y-%m-%dT%H:%M:%fZ',
                'now'
            )
        )
);

CREATE INDEX IF NOT EXISTS
    idx_audit_events_created_at
ON audit_events(created_at DESC);

CREATE INDEX IF NOT EXISTS
    idx_audit_events_event_type
ON audit_events(event_type, id DESC);

CREATE INDEX IF NOT EXISTS
    idx_audit_events_actor_user_id
ON audit_events(actor_user_id, id DESC);

CREATE INDEX IF NOT EXISTS
    idx_audit_events_outcome
ON audit_events(outcome, id DESC);

CREATE TRIGGER IF NOT EXISTS
    prevent_audit_event_updates
BEFORE UPDATE ON audit_events
BEGIN
    SELECT RAISE(
        ABORT,
        'audit events are append-only'
    );
END;
)SQL"
            },
            {
                4,
                "add_refresh_token_families",
                R"SQL(
ALTER TABLE auth_sessions
ADD COLUMN token_family_id TEXT NOT NULL
    DEFAULT '';

ALTER TABLE auth_sessions
ADD COLUMN parent_session_id INTEGER;

UPDATE auth_sessions
SET token_family_id =
    'legacy-' || CAST(id AS TEXT)
WHERE token_family_id = '';

CREATE INDEX IF NOT EXISTS
    idx_auth_sessions_token_family_id
ON auth_sessions(token_family_id, id);

CREATE INDEX IF NOT EXISTS
    idx_auth_sessions_parent_session_id
ON auth_sessions(parent_session_id);
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
