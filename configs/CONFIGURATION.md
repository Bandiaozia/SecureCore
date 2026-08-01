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
