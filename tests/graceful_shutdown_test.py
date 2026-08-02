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
from typing import TextIO

HOST = "127.0.0.1"


def find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind((HOST, 0))
        return int(sock.getsockname()[1])


def clean_environment() -> dict[str, str]:
    return {
        key: value
        for key, value in os.environ.items()
        if not key.startswith("SECURECORE_")
    }


class RunningServer:
    def __init__(
        self,
        server_binary: Path,
        grace_period_ms: int,
    ) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory(
            prefix="securecore-shutdown-test-"
        )
        self.root = Path(self.temporary_directory.name)
        self.port = find_free_port()
        self.output_path = self.root / "server-output.log"
        self.output_file: TextIO = self.output_path.open(
            "w+",
            encoding="utf-8",
        )

        config_path = self.root / "server.conf"
        config_path.write_text(
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
                    f"shutdown_grace_period_ms={grace_period_ms}",
                    "tls_enabled=false",
                    "http_max_connections=32",
                    "http_rate_limit_requests=1000",
                    "http_rate_limit_window_seconds=1",
                    "http_max_header_bytes=16384",
                    "http_max_body_bytes=1048576",
                    "http_read_timeout_seconds=5",
                    "http_write_timeout_seconds=5",
                    "http_idle_timeout_seconds=10",
                    "",
                ]
            ),
            encoding="utf-8",
        )

        self.process = subprocess.Popen(
            [str(server_binary), str(config_path)],
            cwd=self.root,
            stdout=self.output_file,
            stderr=subprocess.STDOUT,
            text=True,
            env=clean_environment(),
        )
        self.wait_until_ready()

    def wait_until_ready(self) -> None:
        deadline = time.monotonic() + 8.0
        last_error: Exception | None = None

        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                raise RuntimeError(
                    "SecureCore exited during startup:\n"
                    + self.read_output()
                )

            connection = http.client.HTTPConnection(
                HOST,
                self.port,
                timeout=0.5,
            )

            try:
                connection.request(
                    "GET",
                    "/ready",
                    headers={"Connection": "close"},
                )
                response = connection.getresponse()
                body = response.read()

                if response.status == 200:
                    parsed = json.loads(body.decode("utf-8"))
                    if parsed.get("status") == "ready":
                        return
            except (OSError, http.client.HTTPException) as error:
                last_error = error
            finally:
                connection.close()

            time.sleep(0.05)

        raise RuntimeError(
            "SecureCore did not become ready. "
            f"Last error: {last_error}\n"
            + self.read_output()
        )

    def read_output(self) -> str:
        self.output_file.flush()
        return self.output_path.read_text(encoding="utf-8")

    def terminate(self, timeout: float = 6.0) -> None:
        if self.process.poll() is None:
            self.process.send_signal(signal.SIGTERM)
            try:
                self.process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=timeout)
                raise

    def close(self) -> None:
        try:
            self.terminate()
        finally:
            self.output_file.close()
            self.temporary_directory.cleanup()


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def test_readiness_during_drain(server_binary: Path) -> None:
    server = RunningServer(server_binary, 2000)
    connection = http.client.HTTPConnection(
        HOST,
        server.port,
        timeout=3.0,
    )

    try:
        connection.request("GET", "/health")
        response = connection.getresponse()
        response.read()
        require(response.status == 200, "initial health status")
        require(connection.sock is not None, "persistent connection")

        connection.request("GET", "/metrics")
        metrics_response = connection.getresponse()
        metrics_body = metrics_response.read().decode("utf-8")
        require(metrics_response.status == 200, "metrics status")
        require(
            'securecore_server_state{state="running"} 1'
            in metrics_body,
            "running lifecycle metric",
        )
        require(
            "securecore_http_requests_in_flight" in metrics_body,
            "in-flight request metric",
        )

        server.process.send_signal(signal.SIGTERM)
        time.sleep(0.1)

        connection.request("GET", "/ready")
        draining_response = connection.getresponse()
        draining_body = json.loads(
            draining_response.read().decode("utf-8")
        )

        require(
            draining_response.status == 503,
            "readiness must fail while draining",
        )
        require(
            draining_body.get("status") == "draining",
            "readiness lifecycle body",
        )

        require(
            draining_response.will_close,
            "draining response must close the connection",
        )

        # Explicitly release the client socket before waiting for the
        # server process.  http.client may retain the descriptor briefly
        # even after receiving a Connection: close response, which can
        # otherwise make the integration test race with the drain timer.
        connection.close()

        try:
            server.process.wait(timeout=5.0)
        except subprocess.TimeoutExpired as error:
            raise RuntimeError(
                "server did not exit after the draining response:\n"
                + server.read_output()
            ) from error

        require(server.process.returncode == 0, "graceful exit code")

        output = server.read_output()
        require(
            "Server entered draining state" in output,
            "draining log message",
        )
        require(
            "All HTTP connections drained within the grace period"
            in output,
            "graceful drain completion log",
        )
    except Exception as error:
        raise RuntimeError(
            "readiness-during-drain scenario failed: "
            f"{error}\n===== server output =====\n"
            + server.read_output()
        ) from error
    finally:
        connection.close()
        server.close()


def test_forced_shutdown_after_grace(server_binary: Path) -> None:
    server = RunningServer(server_binary, 300)
    connection = http.client.HTTPConnection(
        HOST,
        server.port,
        timeout=2.0,
    )

    try:
        connection.request("GET", "/health")
        response = connection.getresponse()
        response.read()
        require(response.status == 200, "forced test health status")
        require(connection.sock is not None, "forced test persistent connection")

        started = time.monotonic()
        server.process.send_signal(signal.SIGTERM)
        try:
            server.process.wait(timeout=5.0)
        except subprocess.TimeoutExpired as error:
            raise RuntimeError(
                "server did not exit after forced shutdown:\n"
                + server.read_output()
            ) from error

        elapsed = time.monotonic() - started

        require(server.process.returncode == 0, "forced exit code")
        require(elapsed >= 0.20, "grace period was not observed")
        require(elapsed < 3.0, "forced shutdown took too long")

        output = server.read_output()
        require(
            "Graceful shutdown period expired" in output,
            "grace expiration log",
        )
        require(
            "Forcing connection shutdown" in output,
            "forced shutdown log",
        )
    except Exception as error:
        raise RuntimeError(
            "forced-shutdown scenario failed: "
            f"{error}\n===== server output =====\n"
            + server.read_output()
        ) from error
    finally:
        connection.close()
        server.close()


def main() -> int:
    if len(sys.argv) != 2:
        print(
            "usage: graceful_shutdown_test.py <secure-server>",
            file=sys.stderr,
        )
        return 2

    server_binary = Path(sys.argv[1]).resolve()
    if not server_binary.is_file():
        print(
            f"server executable does not exist: {server_binary}",
            file=sys.stderr,
        )
        return 2

    try:
        test_readiness_during_drain(server_binary)
        test_forced_shutdown_after_grace(server_binary)
    except Exception as error:
        print(
            f"Graceful shutdown integration test failed: {error}",
            file=sys.stderr,
        )
        return 1

    print("Graceful shutdown integration tests passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
