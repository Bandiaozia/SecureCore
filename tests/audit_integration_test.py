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


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind((HOST, 0))
        return int(sock.getsockname()[1])


class Environment:
    def __init__(self, server: Path, admin: Path) -> None:
        self.server_executable = server
        self.admin_executable = admin
        self.temporary_directory = tempfile.TemporaryDirectory(
            prefix="securecore-audit-integration-"
        )
        self.root = Path(self.temporary_directory.name)
        self.port = free_port()
        self.config_path = self.root / "server.conf"
        self.config_path.write_text(
            "\n".join(
                [
                    "environment=test",
                    f"listen_address={HOST}",
                    f"listen_port={self.port}",
                    f"log_file={self.root / 'securecore.log'}",
                    f"database_path={self.root / 'securecore.db'}",
                    "database_pool_size=2",
                    "database_acquire_timeout_ms=500",
                    "io_threads=2",
                    "worker_threads=2",
                    "worker_queue_capacity=32",
                    "shutdown_grace_period_ms=2000",
                    "audit_retention_days=90",
                    "http_rate_limit_requests=1000",
                    "http_rate_limit_window_seconds=1",
                    "",
                ]
            ),
            encoding="utf-8",
        )
        self.process: subprocess.Popen[str] | None = None
        self.output_file = None
        self.output_path = self.root / "server-output.log"

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
            [
                str(self.server_executable),
                str(self.config_path),
            ],
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
        deadline = time.monotonic() + 5
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
            timeout=3,
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

    def promote(self, identifier: str) -> None:
        result = subprocess.run(
            [
                str(self.admin_executable),
                str(self.config_path),
                "promote",
                identifier,
            ],
            cwd=self.root,
            text=True,
            capture_output=True,
            env=self.clean_environment(),
            timeout=10,
            check=False,
        )
        require(
            result.returncode == 0,
            result.stdout + result.stderr,
        )

    def close(self) -> None:
        self.stop()
        self.temporary_directory.cleanup()


def json_body(body: str) -> dict[str, Any]:
    value = json.loads(body)
    require(isinstance(value, dict), body)
    return value


def register(
    environment: Environment,
    username: str,
    email: str,
    password: str,
) -> int:
    status, body, _ = environment.request(
        "POST",
        "/v1/auth/register",
        body={
            "username": username,
            "email": email,
            "password": password,
        },
    )
    require(status == 201, body)
    return int(json_body(body)["user"]["id"])


def login(
    environment: Environment,
    login_value: str,
    password: str,
    *,
    user_agent: str = "audit-integration-test",
) -> tuple[int, dict[str, Any]]:
    status, body, _ = environment.request(
        "POST",
        "/v1/auth/login",
        body={
            "login": login_value,
            "password": password,
        },
        headers={"User-Agent": user_agent},
    )
    return status, json_body(body)


def run(server: Path, admin: Path) -> None:
    environment = Environment(server, admin)
    password = "correct-horse-battery"

    try:
        environment.start()
        admin_id = register(
            environment,
            "rootadmin",
            "rootadmin@example.com",
            password,
        )
        environment.stop()

        environment.promote("rootadmin")
        environment.start()

        status, admin_login = login(
            environment,
            "rootadmin",
            password,
        )
        require(status == 200, json.dumps(admin_login))
        admin_token = str(admin_login["access_token"])

        status, failed_login = login(
            environment,
            "rootadmin",
            "wrong-password",
            user_agent="audit-failure-agent",
        )
        require(status == 401, json.dumps(failed_login))

        user_id = register(
            environment,
            "audituser",
            "audituser@example.com",
            password,
        )

        status, body, _ = environment.request(
            "PATCH",
            f"/v1/admin/users/{user_id}/status",
            body={"enabled": False},
            headers={
                "Authorization": f"Bearer {admin_token}",
                "X-Request-ID": "audit-disable-request",
            },
        )
        require(status == 200, body)

        status, body, headers = environment.request(
            "GET",
            "/v1/admin/audit-events?limit=100&offset=0",
            headers={
                "Authorization": f"Bearer {admin_token}",
                "X-Request-ID": "audit-query-request",
            },
        )
        require(status == 200, body)
        parsed = json_body(body)
        events = parsed.get("events")
        require(isinstance(events, list), body)

        event_types = {
            str(event.get("event_type"))
            for event in events
            if isinstance(event, dict)
        }
        for required_event in {
            "user.register",
            "auth.login",
            "admin.user_disable",
            "admin.cli.promote",
        }:
            require(required_event in event_types, body)

        disable_events = [
            event
            for event in events
            if event.get("event_type") == "admin.user_disable"
        ]
        require(bool(disable_events), body)
        require(
            disable_events[0].get("actor_user_id") == admin_id,
            body,
        )
        require(
            disable_events[0].get("target_id") == user_id,
            body,
        )
        require(
            disable_events[0].get("request_id") ==
            "audit-disable-request",
            body,
        )

        failed_events = [
            event
            for event in events
            if event.get("event_type") == "auth.login"
            and event.get("outcome") == "failure"
        ]
        require(bool(failed_events), body)
        require(
            failed_events[0].get("user_agent") ==
            "audit-failure-agent",
            body,
        )
        require(bool(failed_events[0].get("client_ip")), body)

        serialized = json.dumps(events).lower()
        for forbidden in [
            password.lower(),
            admin_token.lower(),
            "authorization",
            "refresh_token",
            "password_hash",
        ]:
            require(forbidden not in serialized, forbidden)

        status, body, _ = environment.request(
            "GET",
            "/v1/admin/audit-events?event_type=auth.login&outcome=failure",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        require(status == 200, body)
        filtered = json_body(body)["events"]
        require(bool(filtered), body)
        require(
            all(
                event["event_type"] == "auth.login"
                and event["outcome"] == "failure"
                for event in filtered
            ),
            body,
        )

        status, metrics, _ = environment.request("GET", "/metrics")
        require(status == 200, metrics)
        require(
            "securecore_audit_events_recorded_total" in metrics,
            metrics,
        )
        require(
            "securecore_audit_events_failed_total 0" in metrics,
            metrics,
        )

        require(
            headers.get("x-request-id") == "audit-query-request",
            str(headers),
        )
    finally:
        environment.close()


def main() -> int:
    if len(sys.argv) != 3:
        print(
            "usage: audit_integration_test.py <secure-server> <secure-admin>",
            file=sys.stderr,
        )
        return 2

    try:
        run(
            Path(sys.argv[1]).resolve(),
            Path(sys.argv[2]).resolve(),
        )
        print("Security audit integration tests passed.")
        return 0
    except Exception as error:
        print(
            f"Security audit integration test failed: {error}",
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
