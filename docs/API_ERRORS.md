# SecureCore API errors

All JSON error responses use one envelope:

```json
{
  "error": {
    "code": "validation_failed",
    "message": "Request validation failed.",
    "request_id": "client-or-server-request-id",
    "details": [
      {
        "field": "password",
        "reason": "must contain between 8 and 128 bytes"
      }
    ]
  }
}
```

`details` is present only when field-level information is available. The
`X-Request-ID` response header always matches `error.request_id`.

## Status conventions

- `400 Bad Request`: empty body or malformed JSON.
- `401 Unauthorized`: missing, invalid, or expired authentication credentials.
- `403 Forbidden`: authenticated account lacks permission or is disabled.
- `404 Not Found`: route or requested resource does not exist.
- `405 Method Not Allowed`: route exists but does not support the method.
- `409 Conflict`: duplicate user or conflicting account operation.
- `413 Payload Too Large`: configured body limit exceeded.
- `415 Unsupported Media Type`: JSON endpoint did not receive `application/json`.
- `422 Unprocessable Entity`: JSON is syntactically valid but fields fail validation.
- `429 Too Many Requests`: rate limit exceeded.
- `503 Service Unavailable`: overload, connection limit, or graceful shutdown.

Clients should branch on `error.code`, not the human-readable `message`.

## Authentication abuse errors

`login_throttled` uses HTTP `429` and includes a `Retry-After` response header.
It does not reveal whether the submitted login identifier exists.

`refresh_token_reused` uses HTTP `401`. The complete refresh-token family is
revoked before this response is returned, so the client must perform a full
login.

## RBAC errors

Administrative endpoints can return:

- `403 permission_required` when the authenticated user lacks the exact RBAC
  permission required by the endpoint.
- `404 role_not_found` when a requested role does not exist.
- `409 cannot_remove_last_super_admin` when an operation would remove or
  disable the final enabled `super_admin`.
- `409 cannot_remove_base_role` when attempting to revoke the mandatory
  `user` role.
