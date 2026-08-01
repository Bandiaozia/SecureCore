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
            },
            {
                5,
                "create_rbac",
                R"SQL(
CREATE TABLE IF NOT EXISTS roles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    description TEXT NOT NULL DEFAULT '',
    built_in INTEGER NOT NULL DEFAULT 1
        CHECK (built_in IN (0, 1))
);

CREATE TABLE IF NOT EXISTS permissions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    description TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS user_roles (
    user_id INTEGER NOT NULL,
    role_id INTEGER NOT NULL,
    assigned_by_user_id INTEGER,
    assigned_at TEXT NOT NULL DEFAULT (
        strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
    ),
    PRIMARY KEY (user_id, role_id),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE,
    FOREIGN KEY (assigned_by_user_id) REFERENCES users(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS role_permissions (
    role_id INTEGER NOT NULL,
    permission_id INTEGER NOT NULL,
    PRIMARY KEY (role_id, permission_id),
    FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE,
    FOREIGN KEY (permission_id) REFERENCES permissions(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_user_roles_role_id
ON user_roles(role_id, user_id);

CREATE INDEX IF NOT EXISTS idx_role_permissions_permission_id
ON role_permissions(permission_id, role_id);

INSERT OR IGNORE INTO roles(name, description, built_in) VALUES
    ('user', 'Base authenticated user role.', 1),
    ('auditor', 'Can inspect security audit events.', 1),
    ('support', 'Can inspect users and re-enable accounts.', 1),
    ('security_admin', 'Can manage account security and inspect protected metrics.', 1),
    ('super_admin', 'Has every built-in administrative permission.', 1);

INSERT OR IGNORE INTO permissions(name, description) VALUES
    ('users.read', 'Read user profiles and user lists.'),
    ('users.enable', 'Enable disabled user accounts.'),
    ('users.disable', 'Disable user accounts.'),
    ('sessions.read', 'Read user authentication sessions.'),
    ('sessions.revoke', 'Revoke user authentication sessions.'),
    ('audit.read', 'Read security audit events.'),
    ('metrics.read', 'Read protected runtime metrics.'),
    ('roles.manage', 'Assign and revoke RBAC roles.');

INSERT OR IGNORE INTO role_permissions(role_id, permission_id)
SELECT r.id, p.id
FROM roles AS r, permissions AS p
WHERE
    (r.name = 'auditor' AND p.name IN ('audit.read'))
    OR
    (r.name = 'support' AND p.name IN ('users.read', 'users.enable'))
    OR
    (r.name = 'security_admin' AND p.name IN (
        'users.read',
        'users.enable',
        'users.disable',
        'sessions.read',
        'sessions.revoke',
        'audit.read',
        'metrics.read'
    ))
    OR
    (r.name = 'super_admin');

INSERT OR IGNORE INTO user_roles(user_id, role_id)
SELECT u.id, r.id
FROM users AS u
JOIN roles AS r ON r.name = 'user';

INSERT OR IGNORE INTO user_roles(user_id, role_id)
SELECT u.id, r.id
FROM users AS u
JOIN roles AS r ON r.name = 'super_admin'
WHERE u.role = 'admin';

CREATE TRIGGER IF NOT EXISTS assign_default_user_role
AFTER INSERT ON users
BEGIN
    INSERT OR IGNORE INTO user_roles(user_id, role_id)
    SELECT NEW.id, id FROM roles WHERE name = 'user';
END;
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
