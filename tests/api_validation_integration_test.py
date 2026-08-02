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


def find_free_port() -> int:
    with socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM,
    ) as sock:
        sock.bind((HOST, 0))
        return int(sock.getsockname()[1])


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


class TestServer:
    def __init__(self, executable: Path) -> None:
        self.temporary_directory = (
            tempfile.TemporaryDirectory(
                prefix="securecore-api-validation-"
            )
        )

        root = Path(
            self.temporary_directory.name
        )

        self.port = find_free_port()
        self.output_path = root / "server-output.log"
        self.output_file = self.output_path.open(
            "w+",
            encoding="utf-8",
        )

        config_path = root / "server.conf"
        config_path.write_text(
            "\n".join(
                [
                    "environment=test",
                    "registration_enabled=true",
                    f"listen_address={HOST}",
                    f"listen_port={self.port}",
                    f"log_file={root / 'securecore.log'}",
                    f"database_path={root / 'securecore.db'}",
                    "database_pool_size=2",
                    "database_acquire_timeout_ms=500",
                    "io_threads=2",
                    "worker_threads=2",
                    "worker_queue_capacity=32",
                    "shutdown_grace_period_ms=2000",
                    "http_rate_limit_requests=1000",
                    "http_rate_limit_window_seconds=1",
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
            [str(executable), str(config_path)],
            cwd=root,
            stdout=self.output_file,
            stderr=subprocess.STDOUT,
            text=True,
            env=environment,
        )

        self.wait_until_ready()

    def output(self) -> str:
        self.output_file.flush()
        self.output_file.seek(0)
        value = self.output_file.read()
        self.output_file.seek(0, 2)
        return value

    def wait_until_ready(self) -> None:
        deadline = time.monotonic() + 5.0
        last_error: Exception | None = None

        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                raise RuntimeError(
                    "server exited during startup\n"
                    + self.output()
                )

            try:
                status, body, _ = self.request(
                    "GET",
                    "/health",
                )

                if (
                    status == 200
                    and json.loads(body)
                    == {"status": "ok"}
                ):
                    return
            except (
                OSError,
                ValueError,
                http.client.HTTPException,
            ) as error:
                last_error = error

            time.sleep(0.05)

        raise RuntimeError(
            f"server did not become ready: {last_error}\n"
            + self.output()
        )

    def request(
        self,
        method: str,
        target: str,
        *,
        body: str | bytes | None = None,
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
                body=body,
                headers=headers or {},
            )

            response = connection.getresponse()
            response_body = response.read().decode(
                "utf-8",
                errors="replace",
            )

            response_headers = {
                name.lower(): value
                for name, value
                in response.getheaders()
            }

            return (
                response.status,
                response_body,
                response_headers,
            )
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
        self.temporary_directory.cleanup()


def parse_api_error(
    status: int,
    body: str,
    headers: dict[str, str],
    expected_status: int,
    expected_code: str,
) -> dict[str, Any]:
    require(status == expected_status, body)

    parsed = json.loads(body)
    require(
        isinstance(parsed.get("error"), dict),
        body,
    )

    error = parsed["error"]

    require(
        error.get("code") == expected_code,
        body,
    )

    require(
        isinstance(error.get("message"), str)
        and bool(error["message"]),
        body,
    )

    require(
        error.get("request_id")
        == headers.get("x-request-id"),
        body,
    )

    return error


def run_tests(executable: Path) -> None:
    server = TestServer(executable)

    try:
        status, body, headers = server.request(
            "GET",
            "/missing",
            headers={
                "X-Request-ID":
                    "client-validation-1"
            },
        )

        error = parse_api_error(
            status,
            body,
            headers,
            404,
            "not_found",
        )

        require(
            error["request_id"] ==
                "client-validation-1",
            body,
        )

        status, body, headers = server.request(
            "POST",
            "/v1/auth/register",
            body=json.dumps(
                {
                    "username": "x",
                    "email": "invalid",
                    "password": "short",
                }
            ),
            headers={
                "Content-Type":
                    "application/json"
            },
        )

        error = parse_api_error(
            status,
            body,
            headers,
            422,
            "validation_failed",
        )

        detail_fields = {
            detail["field"]
            for detail in error.get("details", [])
        }

        require(
            detail_fields == {
                "username",
                "email",
                "password",
            },
            body,
        )

        status, body, headers = server.request(
            "POST",
            "/v1/auth/login",
            body=json.dumps(
                {
                    "login": 42,
                }
            ),
            headers={
                "Content-Type":
                    "application/json"
            },
        )

        error = parse_api_error(
            status,
            body,
            headers,
            422,
            "validation_failed",
        )

        detail_fields = {
            detail["field"]
            for detail in error.get("details", [])
        }

        require(
            detail_fields == {
                "login",
                "password",
            },
            body,
        )

        status, body, headers = server.request(
            "POST",
            "/v1/auth/register",
            body='{"username":}',
            headers={
                "Content-Type":
                    "application/json"
            },
        )

        parse_api_error(
            status,
            body,
            headers,
            400,
            "invalid_json",
        )

        status, body, headers = server.request(
            "POST",
            "/v1/auth/register",
            body="{}",
            headers={
                "Content-Type": "text/plain"
            },
        )

        parse_api_error(
            status,
            body,
            headers,
            415,
            "unsupported_media_type",
        )

        registration = {
            "username": "validation_user",
            "email": "validation@example.com",
            "password": "secure-password-123",
        }

        status, body, _ = server.request(
            "POST",
            "/v1/auth/register",
            body=json.dumps(registration),
            headers={
                "Content-Type":
                    "application/json"
            },
        )

        require(status == 201, body)

        status, body, headers = server.request(
            "POST",
            "/v1/auth/register",
            body=json.dumps(registration),
            headers={
                "Content-Type":
                    "application/json"
            },
        )

        parse_api_error(
            status,
            body,
            headers,
            409,
            "duplicate_user",
        )

        status, body, headers = server.request(
            "GET",
            "/v1/users/me",
        )

        error = parse_api_error(
            status,
            body,
            headers,
            401,
            "missing_access_token",
        )

        require(
            headers.get("www-authenticate") ==
                "Bearer",
            body,
        )

        require(
            error["request_id"] ==
                headers["x-request-id"],
            body,
        )
    except Exception as error:
        raise RuntimeError(
            f"API validation integration test failed: {error}\n"
            "===== server output =====\n"
            + server.output()
        ) from error
    finally:
        server.close()


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit(
            "Usage: api_validation_integration_test.py "
            "<secure-server executable>"
        )

    executable_path = Path(sys.argv[1]).resolve()

    if not executable_path.is_file():
        raise SystemExit(
            f"Server executable does not exist: "
            f"{executable_path}"
        )

    run_tests(executable_path)
    print("API validation integration tests passed.")
