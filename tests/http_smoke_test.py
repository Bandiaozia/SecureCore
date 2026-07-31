#!/usr/bin/env python3

from __future__ import annotations

import concurrent.futures
import http.client
import json
import signal
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from typing import Any


HOST = "127.0.0.1"
SERVER_BINARY = ""


def find_free_port() -> int:
    """让操作系统分配一个当前可用的本地端口。"""
    with socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM
    ) as sock:
        sock.bind((HOST, 0))
        return int(sock.getsockname()[1])


class SecureCoreHttpTests(unittest.TestCase):
    process: subprocess.Popen[str]
    port: int
    temporary_directory: tempfile.TemporaryDirectory[str]
    output_file: Any

    @classmethod
    def setUpClass(cls) -> None:
        server_path = Path(
            SERVER_BINARY
        ).resolve()

        if not server_path.is_file():
            raise RuntimeError(
                f"Server executable does not exist: "
                f"{server_path}"
            )

        cls.temporary_directory = (
            tempfile.TemporaryDirectory(
                prefix="securecore-http-test-"
            )
        )

        temporary_path = Path(
            cls.temporary_directory.name
        )

        cls.port = find_free_port()

        config_path = (
            temporary_path / "server.conf"
        )

        log_path = (
            temporary_path / "securecore.log"
        )

        config_path.write_text(
            "\n".join(
                [
                    f"listen_address={HOST}",
                    f"listen_port={cls.port}",
                    f"log_file={log_path}",
                    "io_threads=4",
                    "http_max_header_bytes=1024",
                    "http_max_body_bytes=256",
                    "http_read_timeout_seconds=1",
                    "http_write_timeout_seconds=3",
                    "http_idle_timeout_seconds=3",
                    "",
                ]
            ),
            encoding="utf-8",
        )

        output_path = (
            temporary_path / "server-output.log"
        )

        cls.output_file = output_path.open(
            "w+",
            encoding="utf-8"
        )

        cls.process = subprocess.Popen(
            [
                str(server_path),
                str(config_path),
            ],
            cwd=temporary_path,
            stdout=cls.output_file,
            stderr=subprocess.STDOUT,
            text=True,
        )

        cls.wait_until_ready()

    @classmethod
    def tearDownClass(cls) -> None:
        if hasattr(cls, "process"):
            if cls.process.poll() is None:
                cls.process.send_signal(
                    signal.SIGTERM
                )

                try:
                    cls.process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    cls.process.kill()
                    cls.process.wait(timeout=5)

        if hasattr(cls, "output_file"):
            cls.output_file.close()

        if hasattr(
            cls,
            "temporary_directory"
        ):
            cls.temporary_directory.cleanup()

    @classmethod
    def server_output(cls) -> str:
        cls.output_file.flush()
        cls.output_file.seek(0)

        output = cls.output_file.read()

        cls.output_file.seek(
            0,
            2
        )

        return output

    @classmethod
    def wait_until_ready(cls) -> None:
        deadline = time.monotonic() + 5

        while time.monotonic() < deadline:
            if cls.process.poll() is not None:
                raise RuntimeError(
                    "SecureCore exited during startup.\n"
                    + cls.server_output()
                )

            try:
                status, body, _ = cls.request(
                    "GET",
                    "/health"
                )

                if (
                    status == 200
                    and json.loads(body)
                    == {"status": "ok"}
                ):
                    return
            except (
                OSError,
                json.JSONDecodeError,
                http.client.HTTPException,
            ):
                pass

            time.sleep(0.05)

        raise RuntimeError(
            "SecureCore did not become ready.\n"
            + cls.server_output()
        )

    @classmethod
    def request(
        cls,
        method: str,
        target: str,
        *,
        body: bytes | str | None = None,
        headers: dict[str, str] | None = None,
    ) -> tuple[int, str, dict[str, str]]:
        connection = http.client.HTTPConnection(
            HOST,
            cls.port,
            timeout=3
        )

        request_headers = dict(
            headers or {}
        )

        request_body: bytes | str | None = body

        try:
            connection.request(
                method,
                target,
                body=request_body,
                headers=request_headers,
            )

            response = connection.getresponse()

            response_body = response.read().decode(
                "utf-8",
                errors="replace"
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

    def assert_json(
        self,
        method: str,
        target: str,
        expected_status: int,
        expected_body: dict[str, Any],
        *,
        body: bytes | str | None = None,
        headers: dict[str, str] | None = None,
    ) -> dict[str, str]:
        status, response_body, response_headers = (
            self.request(
                method,
                target,
                body=body,
                headers=headers,
            )
        )

        self.assertEqual(
            status,
            expected_status
        )

        self.assertEqual(
            json.loads(response_body),
            expected_body
        )

        return response_headers

    def test_01_health(self) -> None:
        self.assert_json(
            "GET",
            "/health",
            200,
            {"status": "ok"},
        )

    def test_02_health_with_query(self) -> None:
        self.assert_json(
            "GET",
            "/health?detail=true",
            200,
            {"status": "ok"},
        )

    def test_03_missing_route(self) -> None:
        self.assert_json(
            "GET",
            "/missing",
            404,
            {"error": "not_found"},
        )

    def test_04_method_not_allowed(self) -> None:
        headers = self.assert_json(
            "POST",
            "/health",
            405,
            {
                "error":
                    "method_not_allowed"
            },
        )

        self.assertEqual(
            headers.get("allow"),
            "GET"
        )

    def test_05_valid_echo(self) -> None:
        self.assert_json(
            "POST",
            "/v1/echo",
            200,
            {
                "message": "hello",
                "received": True,
            },
            body=json.dumps(
                {"message": "hello"}
            ),
            headers={
                "Content-Type":
                    "application/json"
            },
        )

    def test_06_utf8_echo(self) -> None:
        body = json.dumps(
            {
                "message":
                    "你好，SecureCore"
            },
            ensure_ascii=False,
        ).encode("utf-8")

        self.assert_json(
            "POST",
            "/v1/echo",
            200,
            {
                "message":
                    "你好，SecureCore",
                "received": True,
            },
            body=body,
            headers={
                "Content-Type":
                    "application/json; "
                    "charset=utf-8"
            },
        )

    def test_07_invalid_json(self) -> None:
        self.assert_json(
            "POST",
            "/v1/echo",
            400,
            {"error": "invalid_json"},
            body='{"message":}',
            headers={
                "Content-Type":
                    "application/json"
            },
        )

    def test_08_unsupported_media_type(
        self
    ) -> None:
        self.assert_json(
            "POST",
            "/v1/echo",
            415,
            {
                "error":
                    "unsupported_media_type"
            },
            body='{"message":"hello"}',
            headers={
                "Content-Type":
                    "text/plain"
            },
        )

    def test_09_missing_message(self) -> None:
        self.assert_json(
            "POST",
            "/v1/echo",
            400,
            {"error": "message_required"},
            body="{}",
            headers={
                "Content-Type":
                    "application/json"
            },
        )

    def test_10_wrong_message_type(
        self
    ) -> None:
        self.assert_json(
            "POST",
            "/v1/echo",
            400,
            {
                "error":
                    "message_must_be_string"
            },
            body='{"message":123}',
            headers={
                "Content-Type":
                    "application/json"
            },
        )

    def test_11_empty_body(self) -> None:
        self.assert_json(
            "POST",
            "/v1/echo",
            400,
            {"error": "empty_body"},
            body=b"",
            headers={
                "Content-Type":
                    "application/json"
            },
        )

    def test_12_payload_limit(self) -> None:
        body = json.dumps(
            {
                "message": "a" * 300
            }
        )

        self.assert_json(
            "POST",
            "/v1/echo",
            413,
            {
                "error":
                    "payload_too_large"
            },
            body=body,
            headers={
                "Content-Type":
                    "application/json"
            },
        )

    def test_13_header_limit(self) -> None:
        large_header = "a" * 2000

        raw_request = (
            "GET /health HTTP/1.1\r\n"
            f"Host: {HOST}\r\n"
            f"X-Large: {large_header}\r\n"
            "Connection: close\r\n"
            "\r\n"
        ).encode("ascii")

        with socket.create_connection(
            (HOST, self.port),
            timeout=3
        ) as sock:
            sock.settimeout(3)
            sock.sendall(raw_request)

            chunks: list[bytes] = []

            while True:
                try:
                    chunk = sock.recv(4096)
                except ConnectionResetError:
                    break

                if not chunk:
                    break

                chunks.append(chunk)

        response = b"".join(chunks).decode(
            "utf-8",
            errors="replace"
        )

        self.assertTrue(
            response.startswith(
                "HTTP/1.1 431"
            ),
            response,
        )

        self.assertIn(
            '{"error":"headers_too_large"}',
            response,
        )

    def test_14_read_timeout(self) -> None:
        with socket.create_connection(
            (HOST, self.port),
            timeout=3
        ) as sock:
            sock.settimeout(3)

            sock.sendall(
                b"GET /health HTTP/1.1\r\n"
                b"Host:"
            )

            time.sleep(1.5)

            try:
                received = sock.recv(1024)
            except ConnectionResetError:
                received = b""

            self.assertEqual(
                received,
                b""
            )

    def test_15_concurrent_requests(
        self
    ) -> None:
        request_count = 40

        def send_health_request(
            _: int
        ) -> int:
            status, body, _ = self.request(
                "GET",
                "/health"
            )

            if (
                status != 200
                or json.loads(body)
                != {"status": "ok"}
            ):
                return 0

            return 1

        with concurrent.futures.ThreadPoolExecutor(
            max_workers=8
        ) as executor:
            results = list(
                executor.map(
                    send_health_request,
                    range(request_count),
                )
            )

        self.assertEqual(
            sum(results),
            request_count
        )

    def test_16_connection_limit(self) -> None:
        server_path = Path(
            SERVER_BINARY
        ).resolve()

        with tempfile.TemporaryDirectory(
            prefix="securecore-connection-limit-"
        ) as temporary_directory:
            temporary_path = Path(
                temporary_directory
            )

            port = find_free_port()

            config_path = (
                temporary_path / "server.conf"
            )

            log_path = (
                temporary_path / "securecore.log"
            )

            config_path.write_text(
                "\n".join(
                    [
                        f"listen_address={HOST}",
                        f"listen_port={port}",
                        f"log_file={log_path}",
                        "io_threads=2",
                        "http_max_connections=2",
                        "http_max_header_bytes=16384",
                        "http_max_body_bytes=1048576",
                        "http_read_timeout_seconds=10",
                        "http_write_timeout_seconds=3",
                        "http_idle_timeout_seconds=10",
                        "",
                    ]
                ),
                encoding="utf-8",
            )

            output_path = (
                temporary_path /
                "server-output.log"
            )

            held_connections: list[
                socket.socket
            ] = []

            with output_path.open(
                "w+",
                encoding="utf-8"
            ) as output_file:
                process = subprocess.Popen(
                    [
                        str(server_path),
                        str(config_path),
                    ],
                    cwd=temporary_path,
                    stdout=output_file,
                    stderr=subprocess.STDOUT,
                    text=True,
                )

                try:
                    deadline = (
                        time.monotonic() + 5
                    )

                    while (
                        time.monotonic() <
                        deadline
                    ):
                        if process.poll() is not None:
                            output_file.flush()
                            output_file.seek(0)

                            self.fail(
                                "Connection-limit server "
                                "exited during startup.\n"
                                + output_file.read()
                            )

                        try:
                            connection = (
                                http.client
                                .HTTPConnection(
                                    HOST,
                                    port,
                                    timeout=1,
                                )
                            )

                            connection.request(
                                "GET",
                                "/health",
                            )

                            response = (
                                connection
                                .getresponse()
                            )

                            body = (
                                response
                                .read()
                                .decode("utf-8")
                            )

                            connection.close()

                            if (
                                response.status == 200
                                and json.loads(body)
                                == {"status": "ok"}
                            ):
                                break
                        except (
                            OSError,
                            json.JSONDecodeError,
                            http.client.HTTPException,
                        ):
                            time.sleep(0.05)
                    else:
                        self.fail(
                            "Connection-limit server "
                            "did not become ready"
                        )

                    # 占用两个连接，但不发送完整请求。
                    for _ in range(2):
                        sock = (
                            socket.create_connection(
                                (HOST, port),
                                timeout=3,
                            )
                        )

                        sock.sendall(
                            b"GET /health HTTP/1.1\r\n"
                            b"Host: 127.0.0.1\r\n"
                        )

                        held_connections.append(
                            sock
                        )

                    time.sleep(0.1)

                    # 第三个连接应被服务器直接拒绝。
                    with socket.create_connection(
                        (HOST, port),
                        timeout=3,
                    ) as third:
                        third.settimeout(3)

                        third.sendall(
                            b"GET /health HTTP/1.1\r\n"
                            b"Host: 127.0.0.1\r\n"
                            b"Connection: close\r\n"
                            b"\r\n"
                        )

                        chunks: list[bytes] = []

                        while True:
                            chunk = third.recv(4096)

                            if not chunk:
                                break

                            chunks.append(chunk)

                    raw_response = (
                        b"".join(chunks).decode(
                            "utf-8",
                            errors="replace",
                        )
                    )

                    self.assertTrue(
                        raw_response.startswith(
                            "HTTP/1.1 503"
                        ),
                        raw_response,
                    )

                    self.assertIn(
                        "Retry-After: 1",
                        raw_response,
                    )

                    self.assertIn(
                        '{"error":'
                        '"connection_limit_reached"}',
                        raw_response,
                    )

                finally:
                    for sock in held_connections:
                        sock.close()

                    if process.poll() is None:
                        process.send_signal(
                            signal.SIGTERM
                        )

                        try:
                            process.wait(timeout=5)
                        except subprocess.TimeoutExpired:
                            process.kill()
                            process.wait(timeout=5)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit(
            "Usage: http_smoke_test.py "
            "<secure-server executable>"
        )

    SERVER_BINARY = sys.argv[1]

    # 防止 unittest 把可执行文件路径当作测试名称。
    sys.argv = [sys.argv[0]]

    unittest.main(verbosity=2)
