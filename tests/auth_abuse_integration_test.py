#!/usr/bin/env python3

from __future__ import annotations

import http.client
import json
import os
import signal
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

HOST = "127.0.0.1"
PASSWORD = "correct-horse-battery"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind((HOST, 0))
        return int(sock.getsockname()[1])


class Environment:
    def __init__(self, server: Path) -> None:
        self.server_executable = server
        self.temporary_directory = tempfile.TemporaryDirectory(
            prefix="securecore-auth-abuse-"
        )
        self.root = Path(self.temporary_directory.name)
        self.port = free_port()
        self.database_path = self.root / "securecore.db"
        self.config_path = self.root / "server.conf"
        self.output_path = self.root / "server-output.log"
        self.output_file = None
        self.process: subprocess.Popen[str] | None = None

        self.config_path.write_text(
            "\n".join(
                [
                    "environment=test",
                    f"listen_address={HOST}",
                    f"listen_port={self.port}",
                    f"log_file={self.root / 'securecore.log'}",
                    f"database_path={self.database_path}",
                    "database_pool_size=2",
                    "database_acquire_timeout_ms=500",
                    "io_threads=2",
                    "worker_threads=2",
                    "worker_queue_capacity=32",
                    "shutdown_grace_period_ms=2000",
                    "audit_retention_days=90",
                    "auth_login_account_failure_limit=3",
                    "auth_login_ip_failure_limit=9",
                    "auth_login_failure_window_seconds=60",
                    "auth_login_lockout_seconds=1",
                    "auth_login_max_lockout_seconds=4",
                    "http_rate_limit_requests=1000",
                    "http_rate_limit_window_seconds=1",
                    "",
                ]
            ),
            encoding="utf-8",
        )

    def clean_environment(self) -> dict[str, str]:
        return {
            key: value
            for key, value in os.environ.items()
            if not key.startswith("SECURECORE_")
        }

    def start(self) -> None:
        require(self.process is None, "server already started")
        self.output_file = self.output_path.open(
            "a+",
            encoding="utf-8",
        )
        self.process = subprocess.Popen(
            [str(self.server_executable), str(self.config_path)],
            cwd=self.root,
            stdout=self.output_file,
            stderr=subprocess.STDOUT,
            text=True,
            env=self.clean_environment(),
        )
        self.wait_ready()

    def stop(self) -> None:
        if self.process is None:
            return
        if self.process.poll() is None:
            self.process.send_signal(signal.SIGTERM)
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)
        self.process = None
        if self.output_file is not None:
            self.output_file.close()
            self.output_file = None

    def logs(self) -> str:
        if self.output_file is not None:
            self.output_file.flush()
        if not self.output_path.exists():
            return ""
        return self.output_path.read_text(
            encoding="utf-8",
            errors="replace",
        )

    def wait_ready(self) -> None:
        deadline = time.monotonic() + 8
        last_error: Exception | None = None
        while time.monotonic() < deadline:
            require(self.process is not None, "missing process")
            if self.process.poll() is not None:
                raise RuntimeError(
                    "server exited during startup\n" + self.logs()
                )
            try:
                status, body, _ = self.request("GET", "/ready")
                if status == 200 and json.loads(body)["status"] == "ready":
                    return
            except (OSError, ValueError, http.client.HTTPException) as error:
                last_error = error
            time.sleep(0.05)
        raise RuntimeError(
            f"server did not become ready: {last_error}\n" + self.logs()
        )

    def request(
        self,
        method: str,
        target: str,
        *,
        body: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
    ) -> tuple[int, str, dict[str, str]]:
        connection = http.client.HTTPConnection(
            HOST,
            self.port,
            timeout=5,
        )
        request_headers = dict(headers or {})
        encoded_body: str | None = None
        if body is not None:
            encoded_body = json.dumps(body)
            request_headers.setdefault(
                "Content-Type",
                "application/json",
            )
        try:
            connection.request(
                method,
                target,
                body=encoded_body,
                headers=request_headers,
            )
            response = connection.getresponse()
            response_body = response.read().decode(
                "utf-8",
                errors="replace",
            )
            response_headers = {
                name.lower(): value
                for name, value in response.getheaders()
            }
            return response.status, response_body, response_headers
        finally:
            connection.close()

    def close(self) -> None:
        self.stop()
        self.temporary_directory.cleanup()


def parse_json(body: str) -> dict[str, Any]:
    value = json.loads(body)
    require(isinstance(value, dict), body)
    return value


def error_code(body: str) -> str:
    parsed = parse_json(body)
    error = parsed.get("error")
    require(isinstance(error, dict), body)
    return str(error.get("code"))


def login(
    environment: Environment,
    login_value: str,
    password: str,
) -> tuple[int, dict[str, Any], dict[str, str]]:
    status, body, headers = environment.request(
        "POST",
        "/v1/auth/login",
        body={
            "login": login_value,
            "password": password,
        },
        headers={"User-Agent": "auth-abuse-integration"},
    )
    return status, parse_json(body), headers


def metric_value(metrics: str, name: str) -> int:
    prefix = name + " "
    for line in metrics.splitlines():
        if line.startswith(prefix):
            return int(float(line[len(prefix) :]))
    raise RuntimeError(f"missing metric {name}\n{metrics}")


def run(server: Path) -> None:
    environment = Environment(server)
    first_refresh = ""
    second_access = ""

    try:
        environment.start()

        status, body, _ = environment.request(
            "POST",
            "/v1/auth/register",
            body={
                "username": "protecteduser",
                "email": "protected@example.com",
                "password": PASSWORD,
            },
        )
        require(status == 201, body)

        for attempt in range(2):
            status, body, _ = environment.request(
                "POST",
                "/v1/auth/login",
                body={
                    "login": "protecteduser",
                    "password": f"wrong-password-{attempt}",
                },
            )
            require(status == 401, body)
            require(error_code(body) == "invalid_credentials", body)

        status, body, headers = environment.request(
            "POST",
            "/v1/auth/login",
            body={
                "login": "PROTECTEDUSER",
                "password": "wrong-password-third",
            },
        )
        require(status == 429, body)
        require(error_code(body) == "login_throttled", body)
        require(int(headers.get("retry-after", "0")) >= 1, str(headers))

        status, body, headers = environment.request(
            "POST",
            "/v1/auth/login",
            body={
                "login": "protecteduser",
                "password": PASSWORD,
            },
        )
        require(status == 429, body)
        require(error_code(body) == "login_throttled", body)
        require(int(headers.get("retry-after", "0")) >= 1, str(headers))

        time.sleep(1.2)

        status, successful_login, _ = login(
            environment,
            "protecteduser",
            PASSWORD,
        )
        require(status == 200, json.dumps(successful_login))
        first_refresh = str(successful_login["refresh_token"])

        status, body, _ = environment.request(
            "POST",
            "/v1/auth/refresh",
            body={"refresh_token": first_refresh},
        )
        require(status == 200, body)
        rotated = parse_json(body)
        second_access = str(rotated["access_token"])

        status, body, _ = environment.request(
            "POST",
            "/v1/auth/refresh",
            body={"refresh_token": first_refresh},
        )
        require(status == 401, body)
        require(error_code(body) == "refresh_token_reused", body)

        status, body, _ = environment.request(
            "GET",
            "/v1/users/me",
            headers={"Authorization": f"Bearer {second_access}"},
        )
        require(status == 401, body)
        require(error_code(body) == "invalid_access_token", body)

        # The successful login cleared the account dimension but deliberately
        # did not reset the source-IP total. These distinct accounts bring the
        # existing three source-IP failures to the configured threshold of 9.
        for attempt in range(5):
            status, body, _ = environment.request(
                "POST",
                "/v1/auth/login",
                body={
                    "login": f"missing-user-{attempt}",
                    "password": "not-the-password",
                },
            )
            require(status == 401, body)

        status, body, _ = environment.request(
            "POST",
            "/v1/auth/login",
            body={
                "login": "missing-user-final",
                "password": "not-the-password",
            },
        )
        require(status == 429, body)
        require(error_code(body) == "login_throttled", body)

        status, metrics, _ = environment.request("GET", "/metrics")
        require(status == 200, metrics)
        require(
            metric_value(metrics, "securecore_auth_login_success_total") >= 1,
            metrics,
        )
        require(
            metric_value(metrics, "securecore_auth_login_failure_total") >= 9,
            metrics,
        )
        require(
            metric_value(metrics, "securecore_auth_login_throttled_total") >= 3,
            metrics,
        )
        require(
            metric_value(metrics, "securecore_auth_refresh_reuse_total") == 1,
            metrics,
        )
    finally:
        environment.stop()

    with sqlite3.connect(environment.database_path) as database:
        event_rows = database.execute(
            "SELECT event_type, metadata_json FROM audit_events "
            "WHERE event_type IN (?, ?) ORDER BY id",
            ("auth.login_throttled", "auth.refresh_reuse"),
        ).fetchall()
        require(
            any(row[0] == "auth.login_throttled" for row in event_rows),
            str(event_rows),
        )
        require(
            any(row[0] == "auth.refresh_reuse" for row in event_rows),
            str(event_rows),
        )

        serialized = json.dumps(event_rows).lower()
        for forbidden in [
            PASSWORD.lower(),
            first_refresh.lower(),
            second_access.lower(),
            "authorization",
            "password_hash",
        ]:
            require(forbidden not in serialized, forbidden)

        family_rows = database.execute(
            "SELECT token_family_id, parent_session_id, revoked "
            "FROM auth_sessions ORDER BY id"
        ).fetchall()
        require(len(family_rows) >= 2, str(family_rows))
        require(bool(family_rows[0][0]), str(family_rows))
        require(family_rows[1][1] is not None, str(family_rows))
        require(
            all(int(row[2]) == 1 for row in family_rows[:2]),
            str(family_rows),
        )

    environment.close()


def main() -> int:
    if len(sys.argv) != 2:
        print(
            "usage: auth_abuse_integration_test.py <secure-server>",
            file=sys.stderr,
        )
        return 2

    try:
        run(Path(sys.argv[1]).resolve())
        print("Authentication abuse integration tests passed.")
        return 0
    except Exception as error:
        print(
            f"Authentication abuse integration test failed: {error}",
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
