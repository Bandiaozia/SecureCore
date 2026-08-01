# Authentication abuse protection

SecureCore applies defense in depth to login and refresh-token endpoints.

## Login failures

Failed login attempts are tracked by both normalized login identifier and
client IP. Either dimension can temporarily reject further attempts. Repeated
lockouts use exponential backoff, capped by the configured maximum.

A rejected login returns:

```http
HTTP/1.1 429 Too Many Requests
Retry-After: 300
```

```json
{
  "error": {
    "code": "login_throttled",
    "message": "Too many failed login attempts were made. Try again later.",
    "request_id": "..."
  }
}
```

The tracker is process-local and intentionally contains no password or token
material. A successful login clears the matching account state. IP-wide
failures remain until the configured window expires so a valid account cannot
reset a shared
source-address lockout.

## User-enumeration timing

A login for an unknown account still performs one Argon2id password
verification using a startup-generated dummy password hash. The API continues
to return the same `invalid_credentials` error for an unknown account and an
incorrect password.

## Refresh-token families

Each initial login creates a random token-family identifier. Every refresh
rotation creates a child session in the same family and revokes the parent.
If a previously revoked refresh token is submitted again, SecureCore treats it
as possible token theft and revokes every active session in that family.

The response is HTTP `401` with error code `refresh_token_reused`. Clients must
perform a full login after this event.

## Audit and metrics

Audit event types:

- `auth.login_throttled`
- `auth.refresh_reuse`

Prometheus counters:

- `securecore_auth_login_success_total`
- `securecore_auth_login_failure_total`
- `securecore_auth_login_throttled_total`
- `securecore_auth_refresh_reuse_total`

No plaintext passwords, password hashes, access tokens, refresh tokens, or
Authorization headers are written to the audit log.
