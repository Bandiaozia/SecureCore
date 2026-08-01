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
