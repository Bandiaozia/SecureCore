# SecureCore role-based access control

Schema migration 5 introduces normalized RBAC tables:

- `roles`
- `permissions`
- `user_roles`
- `role_permissions`

Existing `users.role='admin'` accounts are migrated to `super_admin`. The
legacy `users.role` field remains as a compatibility alias (`user` or `admin`),
but authorization decisions are made only from the RBAC tables.

## Built-in roles

| Role | Permissions |
| --- | --- |
| `user` | no administrative permissions |
| `auditor` | `audit.read` |
| `support` | `users.read`, `users.enable` |
| `security_admin` | user, session, audit, and metrics security permissions |
| `super_admin` | every built-in permission |

Built-in permissions are:

- `users.read`
- `users.enable`
- `users.disable`
- `sessions.read`
- `sessions.revoke`
- `audit.read`
- `metrics.read`
- `roles.manage`

## HTTP API

All endpoints require a Bearer access token with `roles.manage`:

- `GET /v1/admin/roles`
- `GET /v1/admin/permissions`
- `GET /v1/admin/users/{id}/roles`
- `POST /v1/admin/users/{id}/roles` with `{"role":"support"}`
- `DELETE /v1/admin/users/{id}/roles/{role}`

Role assignment and revocation are idempotent. The base `user` role cannot be
removed. SecureCore refuses to disable or remove the last enabled
`super_admin`.

Existing administrator APIs now check exact permissions:

- user listing and lookup: `users.read`
- enable account: `users.enable`
- disable account: `users.disable`
- audit event listing: `audit.read`
- protected metrics: `metrics.read`

## Local administration

The original aliases remain supported:

```text
secure-admin server.conf promote user@example.com
secure-admin server.conf demote user@example.com
```

They assign or revoke `super_admin`. Additional commands are:

```text
secure-admin server.conf assign-role user@example.com auditor
secure-admin server.conf revoke-role user@example.com auditor
secure-admin server.conf list-roles user@example.com
secure-admin server.conf roles
secure-admin server.conf permissions
```

Role changes are recorded as security audit events. Passwords, password hashes,
access tokens, refresh tokens, and Authorization headers are never included in
RBAC audit metadata.
