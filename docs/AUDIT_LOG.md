# Security audit log

SecureCore stores security-sensitive actions in the append-only `audit_events`
table. The normal application log is intended for troubleshooting; the audit
log is intended to answer who performed an action, what was targeted, where the
request came from, and whether the operation succeeded.

## Query API

Administrators can query events with:

```text
GET /v1/admin/audit-events
```

Supported query parameters:

- `limit`: 1 to 100, default 50
- `offset`: non-negative integer, default 0
- `actor_user_id`: positive user ID
- `event_type`: exact event type
- `outcome`: `success` or `failure`

The endpoint requires an administrator Bearer token.

## Recorded context

An event may contain:

- actor user ID
- stable event type and success/failure outcome
- target type and target ID
- HTTP request ID
- client IP address
- sanitized User-Agent
- small structured metadata object
- UTC creation time

The HTTP middleware installs request context on the WorkerPool thread, so audit
records created by route handlers receive the same request ID that appears in
the response header and normal access log.

## Sensitive-data rule

Audit metadata must never contain:

- plaintext passwords
- password hashes
- access tokens
- refresh tokens
- Authorization headers
- complete authentication request bodies

The built-in events only store identifiers, result codes, counters, and other
non-secret metadata.

## Retention

`audit_retention_days` controls startup cleanup. Events older than the configured
period are deleted when the server starts. The default is 90 days and the
allowed range is 1 to 3650 days.

Environment override:

```text
SECURECORE_AUDIT_RETENTION_DAYS=180
```

## Metrics

`GET /metrics` exports:

```text
securecore_audit_events_recorded_total
securecore_audit_events_failed_total
```

A failed audit write does not fail the original user operation. It is logged as
an application error and increments the failure counter.

## Authentication-abuse events

`auth.login_throttled` is written when the account or source-IP failure tracker
rejects a login. Metadata contains only the stable reason and retry duration.

`auth.refresh_reuse` is written when a previously revoked refresh token is
submitted. SecureCore revokes the complete token family before responding.
Passwords and token values are never included.

## RBAC events

Role management appends `rbac.role_assign` and `rbac.role_revoke` events. Local
CLI operations use `admin.cli.assign-role`, `admin.cli.revoke-role`,
`admin.cli.promote`, and `admin.cli.demote`. Metadata contains only the role
name and whether the assignment changed; credentials and tokens are excluded.
