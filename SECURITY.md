# Security policy

## Supported versions

Security fixes are provided for the latest published release and the `main`
branch.

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability. Use GitHub's
**Security** tab and select **Report a vulnerability** to submit a private
security advisory to the maintainers.

Include the affected version, configuration, reproduction steps, expected
impact, and any proposed mitigation. Please allow the maintainers reasonable
time to investigate and publish a coordinated fix before public disclosure.

## Security boundaries

SecureCore protects network requests, authentication state, authorization,
and audit records within the running service. It does not encrypt the SQLite
database or log files at rest. Deployments must protect the host account,
configuration, database, logs, backups, and TLS private keys with operating
system access controls and storage encryption where required.
