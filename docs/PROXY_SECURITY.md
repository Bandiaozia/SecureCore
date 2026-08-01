# Reverse proxy, CORS, and HSTS security

SecureCore derives a client address from forwarding headers only when the
immediate TCP peer matches `trusted_proxy_cidrs`. Requests from every other
peer use the socket address and ignore all forwarding headers.

Supported headers, in precedence order, are:

1. RFC 7239 `Forwarded`
2. `X-Forwarded-For`
3. `X-Real-IP`

The effective secure scheme comes from `Forwarded: proto=` or
`X-Forwarded-Proto` only for a trusted peer. This controls HSTS emission; it
never changes TLS itself.

The chain is processed from right to left. Trusted proxy hops are removed and
the first untrusted address becomes the effective client. The address is then
used by rate limiting, authentication-abuse protection, access logging, and
audit logging.

A reverse proxy must overwrite untrusted forwarding headers or append its
verified peer address. Do not place client-accessible address ranges in
`trusted_proxy_cidrs`.

Example for a local Nginx/Caddy deployment:

```ini
listen_address=127.0.0.1
trusted_proxy_cidrs=127.0.0.1/32,::1/128
proxy_forwarded_header_max_bytes=4096
cors_allowed_origins=https://app.example.com
cors_allow_credentials=false
hsts_enabled=true
hsts_max_age_seconds=31536000
hsts_include_subdomains=true
hsts_preload=false
```

SecureCore accepts normal HTTP/HTTPS forwarding headers. It does not implement
the HAProxy binary PROXY protocol.
