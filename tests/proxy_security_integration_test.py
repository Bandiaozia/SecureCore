#!/usr/bin/env python3

from __future__ import annotations

import http.client
import json
import os
import signal
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any


HOST = "127.0.0.1"
SERVER_BINARY = ""


def find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind((HOST, 0))
        return int(sock.getsockname()[1])


class ManagedServer:
    def __init__(
        self,
        root: Path,
        name: str,
        *,
        trusted_proxy_cidrs: str,
        rate_limit: int,
    ) -> None:
        self.root = root / name
        self.root.mkdir(parents=True)
        self.port = find_free_port()
        self.output_path = self.root / "server-output.log"
        self.output_file: Any = self.output_path.open(
            "w+",
            encoding="utf-8",
        )

        config_path = self.root / "server.conf"
        config_path.write_text(
            "\n".join(
                [
                    "environment=test",
                    f"listen_address={HOST}",
                    f"listen_port={self.port}",
                    f"log_file={self.root / 'server.log'}",
                    f"database_path={self.root / 'server.db'}",
                    "database_pool_size=2",
                    "database_acquire_timeout_ms=500",
                    "io_threads=2",
                    "worker_threads=2",
                    "worker_queue_capacity=32",
                    "shutdown_grace_period_ms=1000",
                    "audit_retention_days=90",
                    "metrics_require_auth=false",
                    "auth_login_account_failure_limit=5",
                    "auth_login_ip_failure_limit=20",
                    "auth_login_failure_window_seconds=300",
                    "auth_login_lockout_seconds=300",
                    "auth_login_max_lockout_seconds=3600",
                    "tls_enabled=false",
                    f"trusted_proxy_cidrs={trusted_proxy_cidrs}",
                    "proxy_forwarded_header_max_bytes=128",
                    "cors_allowed_origins=https://allowed.example",
                    "cors_allow_credentials=true",
                    "cors_max_age_seconds=120",
                    "hsts_enabled=true",
                    "hsts_max_age_seconds=12345",
                    "hsts_include_subdomains=true",
                    "hsts_preload=false",
                    "http_max_connections=64",
                    f"http_rate_limit_requests={rate_limit}",
                    "http_rate_limit_window_seconds=30",
                    "http_max_header_bytes=4096",
                    "http_max_body_bytes=4096",
                    "http_read_timeout_seconds=2",
                    "http_write_timeout_seconds=2",
                    "http_idle_timeout_seconds=2",
                    "",
                ]
            ),
            encoding="utf-8",
        )

        environment = {
            key: value
            for key, value in os.environ.items()
            if not key.startswith("SECURECORE_")
        }

        self.process = subprocess.Popen(
            [SERVER_BINARY, str(config_path)],
            cwd=self.root,
            stdout=self.output_file,
            stderr=subprocess.STDOUT,
            text=True,
            env=environment,
        )

        self.wait_for_port()

    def output(self) -> str:
        self.output_file.flush()
        self.output_file.seek(0)
        content = self.output_file.read()
        self.output_file.seek(0, 2)
        return content

    def wait_for_port(self) -> None:
        deadline = time.monotonic() + 6

        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                raise RuntimeError(
                    "SecureCore exited during startup.\n" + self.output()
                )

            try:
                with socket.create_connection(
                    (HOST, self.port),
                    timeout=0.2,
                ):
                    return
            except OSError:
                time.sleep(0.05)

        raise RuntimeError(
            "SecureCore did not open its port.\n" + self.output()
        )

    def request(
        self,
        method: str,
        target: str,
        *,
        headers: dict[str, str] | None = None,
    ) -> tuple[int, str, dict[str, str]]:
        connection = http.client.HTTPConnection(
            HOST,
            self.port,
            timeout=3,
        )

        try:
            connection.request(
                method,
                target,
                headers=dict(headers or {}),
            )
            response = connection.getresponse()
            body = response.read().decode("utf-8", errors="replace")
            response_headers = {
                name.lower(): value
                for name, value in response.getheaders()
            }
            return response.status, body, response_headers
        finally:
            connection.close()

    def close(self) -> None:
        if self.process.poll() is None:
            self.process.send_signal(signal.SIGTERM)
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)

        self.output_file.close()


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def error_code(body: str) -> str:
    payload = json.loads(body)
    return str(payload["error"]["code"])


def test_forwarding_cors_and_hsts(root: Path) -> None:
    server = ManagedServer(
        root,
        "trusted-policy",
        trusted_proxy_cidrs="127.0.0.1/32",
        rate_limit=100,
    )

    try:
        status, _, headers = server.request(
            "GET",
            "/health",
            headers={
                "X-Forwarded-For": "198.51.100.10",
                "X-Forwarded-Proto": "https",
                "Origin": "https://allowed.example",
            },
        )
        require(status == 200, "trusted forwarded request failed")
        require(
            headers.get("strict-transport-security")
            == "max-age=12345; includeSubDomains",
            "trusted HTTPS forwarding did not enable HSTS",
        )
        require(
            headers.get("access-control-allow-origin")
            == "https://allowed.example",
            "allowed CORS origin was not echoed",
        )
        require(
            headers.get("access-control-allow-credentials") == "true",
            "CORS credentials header is missing",
        )
        require(
            "origin" in headers.get("vary", "").lower(),
            "CORS response is missing Vary: Origin",
        )

        status, body, _ = server.request(
            "GET",
            "/health",
            headers={
                "X-Forwarded-For": "198.51.100.11",
                "Origin": "https://evil.example",
            },
        )
        require(status == 403, "disallowed CORS origin was accepted")
        require(
            error_code(body) == "cors_origin_denied",
            "wrong CORS denial error code",
        )

        status, _, headers = server.request(
            "OPTIONS",
            "/v1/auth/login",
            headers={
                "X-Forwarded-For": "198.51.100.12",
                "Origin": "https://allowed.example",
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "Content-Type, Authorization",
            },
        )
        require(status == 204, "valid CORS preflight failed")
        require(
            "POST" in headers.get("access-control-allow-methods", ""),
            "preflight response is missing allowed methods",
        )

        status, body, _ = server.request(
            "OPTIONS",
            "/v1/auth/login",
            headers={
                "X-Forwarded-For": "198.51.100.13",
                "Origin": "https://allowed.example",
                "Access-Control-Request-Method": "TRACE",
            },
        )
        require(status == 403, "invalid preflight method was accepted")
        require(
            error_code(body) == "cors_preflight_denied",
            "wrong preflight denial error code",
        )

        status, body, _ = server.request(
            "GET",
            "/health",
            headers={"X-Forwarded-For": "unknown"},
        )
        require(status == 400, "malformed forwarding header was accepted")
        require(
            error_code(body) == "invalid_forwarded_header",
            "wrong malformed forwarding error code",
        )

        status, body, _ = server.request(
            "GET",
            "/health",
            headers={"X-Forwarded-For": "1" * 200},
        )
        require(status == 400, "oversized forwarding header was accepted")
        require(
            error_code(body) == "forwarded_header_too_large",
            "wrong oversized forwarding error code",
        )

        status, _, headers = server.request(
            "GET",
            "/health",
            headers={"X-Forwarded-For": "198.51.100.14"},
        )
        require(status == 200, "plain forwarded request failed")
        require(
            "strict-transport-security" not in headers,
            "HSTS was emitted for known plain HTTP",
        )
    except Exception as error:
        raise RuntimeError(
            f"trusted proxy policy scenario failed: {error}\n"
            f"===== server output =====\n{server.output()}"
        ) from error
    finally:
        server.close()


def test_rate_limit_uses_resolved_client(root: Path) -> None:
    trusted = ManagedServer(
        root,
        "trusted-rate",
        trusted_proxy_cidrs="127.0.0.1/32",
        rate_limit=1,
    )

    try:
        status, _, _ = trusted.request(
            "GET",
            "/health",
            headers={"X-Forwarded-For": "198.51.100.21"},
        )
        require(status == 200, "first forwarded client was rejected")

        status, _, _ = trusted.request(
            "GET",
            "/health",
            headers={"X-Forwarded-For": "198.51.100.22"},
        )
        require(status == 200, "distinct forwarded client shared a rate bucket")

        status, _, _ = trusted.request(
            "GET",
            "/health",
            headers={"X-Forwarded-For": "198.51.100.21"},
        )
        require(status == 429, "same forwarded client bypassed rate limiting")
    finally:
        trusted.close()

    untrusted = ManagedServer(
        root,
        "untrusted-rate",
        trusted_proxy_cidrs="none",
        rate_limit=1,
    )

    try:
        status, _, headers = untrusted.request(
            "GET",
            "/health",
            headers={
                "X-Forwarded-For": "198.51.100.31",
                "X-Forwarded-Proto": "https",
            },
        )
        require(status == 200, "first direct request failed")
        require(
            "strict-transport-security" not in headers,
            "untrusted client forged HTTPS state",
        )

        status, _, _ = untrusted.request(
            "GET",
            "/health",
            headers={"X-Forwarded-For": "198.51.100.32"},
        )
        require(
            status == 429,
            "untrusted X-Forwarded-For bypassed peer-IP rate limiting",
        )
    finally:
        untrusted.close()


def main() -> int:
    global SERVER_BINARY

    if len(sys.argv) != 2:
        print(
            "usage: proxy_security_integration_test.py <secure-server>",
            file=sys.stderr,
        )
        return 2

    SERVER_BINARY = str(Path(sys.argv[1]).resolve())

    try:
        with tempfile.TemporaryDirectory(
            prefix="securecore-proxy-security-test-"
        ) as directory:
            root = Path(directory)
            test_forwarding_cors_and_hsts(root)
            test_rate_limit_uses_resolved_client(root)

        print("Proxy security integration tests passed.")
        return 0
    except Exception as error:
        print(
            f"Proxy security integration test failed: {error}",
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
