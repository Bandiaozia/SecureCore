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
