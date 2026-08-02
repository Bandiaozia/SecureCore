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
            prefix="securecore-rbac-integration-"
        )
        self.root = Path(self.temporary_directory.name)
        self.port = free_port()
        self.config_path = self.root / "server.conf"
        self.config_path.write_text(
            "\n".join(
                [
                    "environment=test",
                    "registration_enabled=true",
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
                    "metrics_require_auth=true",
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
        self.output_file = self.output_path.open("a+", encoding="utf-8")
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
        return self.output_path.read_text(encoding="utf-8", errors="replace")

    def wait_ready(self) -> None:
        deadline = time.monotonic() + 5
        last_error: Exception | None = None
        while time.monotonic() < deadline:
            require(self.process is not None, "missing process")
            if self.process.poll() is not None:
                raise RuntimeError("server exited during startup\n" + self.logs())
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
        token: str | None = None,
    ) -> tuple[int, str, dict[str, str]]:
        connection = http.client.HTTPConnection(HOST, self.port, timeout=3)
        headers: dict[str, str] = {}
        encoded_body: str | None = None
        if body is not None:
            encoded_body = json.dumps(body)
            headers["Content-Type"] = "application/json"
        if token is not None:
            headers["Authorization"] = f"Bearer {token}"
        try:
            connection.request(
                method,
                target,
                body=encoded_body,
                headers=headers,
            )
            response = connection.getresponse()
            response_body = response.read().decode("utf-8", errors="replace")
            return (
                response.status,
                response_body,
                {name.lower(): value for name, value in response.getheaders()},
            )
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
        require(result.returncode == 0, result.stdout + result.stderr)

    def close(self) -> None:
        self.stop()
        self.temporary_directory.cleanup()


def parse_object(body: str) -> dict[str, Any]:
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
        body={"username": username, "email": email, "password": password},
    )
    require(status == 201, body)
    return int(parse_object(body)["user"]["id"])


def login(environment: Environment, username: str, password: str) -> str:
    status, body, _ = environment.request(
        "POST",
        "/v1/auth/login",
        body={"login": username, "password": password},
    )
    require(status == 200, body)
    return str(parse_object(body)["access_token"])


def error_code(body: str) -> str:
    return str(parse_object(body)["error"]["code"])


def run(server: Path, admin: Path) -> None:
    environment = Environment(server, admin)
    password = "correct-horse-battery"

    try:
        environment.start()
        root_id = register(
            environment, "rootadmin", "root@example.com", password
        )
        support_id = register(
            environment, "supportuser", "support@example.com", password
        )
        environment.stop()

        environment.promote("rootadmin")
        environment.start()

        root_token = login(environment, "rootadmin", password)

        status, body, _ = environment.request(
            "GET", "/v1/admin/roles", token=root_token
        )
        require(status == 200, body)
        roles = parse_object(body)["roles"]
        role_names = {str(role["name"]) for role in roles}
        require(
            role_names == {
                "user",
                "auditor",
                "support",
                "security_admin",
                "super_admin",
            },
            body,
        )
        super_admin = next(
            role for role in roles if role["name"] == "super_admin"
        )
        super_permissions = {
            str(permission["name"])
            for permission in super_admin["permissions"]
        }
        require("roles.manage" in super_permissions, body)
        require("metrics.read" in super_permissions, body)

        status, body, _ = environment.request(
            "GET", "/v1/admin/permissions", token=root_token
        )
        require(status == 200, body)
        require(len(parse_object(body)["permissions"]) == 8, body)

        status, body, _ = environment.request(
            "POST",
            f"/v1/admin/users/{support_id}/roles",
            body={"role": "support"},
            token=root_token,
        )
        require(status == 200, body)
        require(parse_object(body)["changed"] is True, body)

        support_token = login(environment, "supportuser", password)
        status, body, _ = environment.request(
            "GET", "/v1/admin/users?limit=10&offset=0", token=support_token
        )
        require(status == 200, body)

        status, body, _ = environment.request(
            "PATCH",
            f"/v1/admin/users/{root_id}/status",
            body={"enabled": False},
            token=support_token,
        )
        require(status == 403, body)
        require(error_code(body) == "permission_required", body)

        status, body, _ = environment.request(
            "GET", "/v1/admin/audit-events", token=support_token
        )
        require(status == 403, body)

        status, body, _ = environment.request("GET", "/metrics")
        require(status == 401, body)
        status, body, _ = environment.request(
            "GET", "/metrics", token=support_token
        )
        require(status == 403, body)
        status, metrics, _ = environment.request(
            "GET", "/metrics", token=root_token
        )
        require(status == 200, metrics)
        require("securecore_up 1" in metrics, metrics)

        status, body, _ = environment.request(
            "DELETE",
            f"/v1/admin/users/{support_id}/roles/support",
            token=root_token,
        )
        require(status == 200, body)
        require(parse_object(body)["changed"] is True, body)

        status, body, _ = environment.request(
            "GET", "/v1/admin/users", token=support_token
        )
        require(status == 403, body)

        status, body, _ = environment.request(
            "POST",
            f"/v1/admin/users/{support_id}/roles",
            body={"role": "auditor"},
            token=root_token,
        )
        require(status == 200, body)

        status, body, _ = environment.request(
            "GET", "/v1/admin/audit-events", token=support_token
        )
        require(status == 200, body)
        events = parse_object(body)["events"]
        event_types = {
            str(event["event_type"])
            for event in events
            if isinstance(event, dict)
        }
        require("rbac.role_assign" in event_types, body)
        require("rbac.role_revoke" in event_types, body)

        status, body, _ = environment.request(
            "DELETE",
            f"/v1/admin/users/{root_id}/roles/super_admin",
            token=root_token,
        )
        require(status == 409, body)
        require(
            error_code(body) == "cannot_remove_last_super_admin",
            body,
        )

        status, body, _ = environment.request(
            "GET",
            f"/v1/admin/users/{support_id}/roles",
            token=root_token,
        )
        require(status == 200, body)
        assigned = {
            str(role["name"])
            for role in parse_object(body)["roles"]
        }
        require("user" in assigned and "auditor" in assigned, body)
    finally:
        environment.close()


def main() -> int:
    if len(sys.argv) != 3:
        print(
            "usage: rbac_integration_test.py <secure-server> <secure-admin>",
            file=sys.stderr,
        )
        return 2
    try:
        run(Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve())
        print("RBAC integration tests passed.")
        return 0
    except Exception as error:
        print(f"RBAC integration test failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
