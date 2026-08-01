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

## Protected metrics

`metrics_require_auth=false` keeps `/metrics` compatible with a private
Prometheus network. Set it to `true` in deployments where the metrics endpoint
is reachable by untrusted clients. Protected metrics require a Bearer token
whose current RBAC roles grant `metrics.read`.

The environment-variable equivalent is
`SECURECORE_METRICS_REQUIRE_AUTH=true`.


## Trusted reverse proxies and client addresses

SecureCore ignores `Forwarded`, `X-Forwarded-For`, `X-Real-IP`, and
`X-Forwarded-Proto` unless the TCP peer matches `trusted_proxy_cidrs`.
Use `none` for direct deployments. A local reverse proxy commonly uses:

```ini
trusted_proxy_cidrs=127.0.0.1/32,::1/128
proxy_forwarded_header_max_bytes=4096
```

The resolver walks the forwarding chain from right to left and removes only
trusted proxy hops. The first untrusted address becomes the effective client
address used by HTTP rate limiting, login-abuse protection, access logs, and
security audit events. Configure the reverse proxy to overwrite or safely
append forwarding headers; never trust an address range that contains normal
clients.

SecureCore supports HTTP forwarding headers, not the HAProxy binary PROXY
protocol. Send ordinary HTTP/HTTPS from the reverse proxy to SecureCore.

## CORS allowlist

`cors_allowed_origins` is an exact, comma-separated origin allowlist. Origins
must include `http://` or `https://` and must not include a path. Development
may use `*`; production mode refuses the wildcard. Credentials cannot be
combined with the wildcard.

```ini
cors_allowed_origins=https://app.example.com,https://admin.example.com
cors_allow_credentials=false
cors_max_age_seconds=600
```

Disallowed origins and invalid preflight methods or headers receive HTTP 403.
Requests without an `Origin` header are unaffected.

## HTTP Strict Transport Security

HSTS is emitted only for requests known to be secure. This includes direct TLS
and `proto=https` / `X-Forwarded-Proto=https` received from a trusted proxy.
Untrusted clients cannot forge the secure-transport decision.

```ini
hsts_enabled=true
hsts_max_age_seconds=31536000
hsts_include_subdomains=true
hsts_preload=false
```

Enable preload only after confirming every subdomain is permanently HTTPS.
