# SecureCore configuration

Configuration precedence is:

1. compiled defaults
2. configuration file
3. `SECURECORE_*` environment variables

Supported environments are `development`, `test`, and `production`.

Production mode refuses plain HTTP on a non-loopback listen address and
requires rate limiting. Plain HTTP is still allowed on `127.0.0.1`, `::1`, or
`localhost` so a local Caddy or Nginx reverse proxy can terminate TLS.

When TLS is enabled, the certificate and private key must be regular files.
The private key must not grant any permissions to group or other users; use
`chmod 600 certs/private-key.pem`.

The startup log prints a redacted configuration summary. Database, log,
certificate, and private-key paths are intentionally omitted.


## Database connection pool

`database_pool_size` controls the number of independent SQLite connections.
`database_acquire_timeout_ms` limits how long a worker waits for a free
connection before the request fails. The same values can be overridden with
`SECURECORE_DATABASE_POOL_SIZE` and
`SECURECORE_DATABASE_ACQUIRE_TIMEOUT_MS`.

File databases use WAL mode so separate pooled connections can read in
parallel. SQLite still serializes write transactions. Plain `:memory:`
databases are automatically restricted to one connection because each
`:memory:` connection owns an isolated database.

## Security audit retention

`audit_retention_days` (or `SECURECORE_AUDIT_RETENTION_DAYS`) controls startup cleanup of audit events older than 1 to 3650 days. The default is 90 days.

## Authentication abuse protection

Login failures are tracked independently by normalized account identifier and
client IP address. The tracker is in memory, so restarting the process clears
active lockouts.

```ini
auth_login_account_failure_limit=5
auth_login_ip_failure_limit=20
auth_login_failure_window_seconds=300
auth_login_lockout_seconds=300
auth_login_max_lockout_seconds=3600
```

When either threshold is reached, `/v1/auth/login` returns HTTP `429` with a
`Retry-After` header. Repeated lockouts double the lockout duration up to the
configured maximum. A successful login clears the matching account state.
IP-wide state expires through the configured failure window so a valid account
cannot reset abuse
from the same source address.

Environment-variable equivalents use the `SECURECORE_` prefix, for example
`SECURECORE_AUTH_LOGIN_ACCOUNT_FAILURE_LIMIT`.
