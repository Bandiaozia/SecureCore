#!/usr/bin/env python3

from __future__ import annotations

import http.client
import json
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from typing import Any


HOST = "127.0.0.1"
SERVER_BINARY = ""
OPENSSL_BINARY = ""


def find_free_port() -> int:
    with socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM,
    ) as sock:
        sock.bind((HOST, 0))
        return int(sock.getsockname()[1])


class SecureCoreHttpsTests(unittest.TestCase):
    process: subprocess.Popen[str]
    port: int
    temporary_directory: tempfile.TemporaryDirectory[str]
    output_file: Any
    client_context: ssl.SSLContext

    @classmethod
    def setUpClass(cls) -> None:
        server_path = Path(
            SERVER_BINARY
        ).resolve()

        openssl_path = Path(
            OPENSSL_BINARY
        ).resolve()

        if not server_path.is_file():
            raise RuntimeError(
                f"Server executable does not exist: "
                f"{server_path}"
            )

        if not openssl_path.is_file():
            raise RuntimeError(
                f"OpenSSL executable does not exist: "
                f"{openssl_path}"
            )

        cls.temporary_directory = (
            tempfile.TemporaryDirectory(
                prefix="securecore-https-test-"
            )
        )

        temporary_path = Path(
            cls.temporary_directory.name
        )

        certificate_path = (
            temporary_path / "certificate.pem"
        )

        private_key_path = (
            temporary_path / "private-key.pem"
        )

        subprocess.run(
            [
                str(openssl_path),
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-sha256",
                "-nodes",
                "-days",
                "1",
                "-subj",
                "/CN=localhost",
                "-keyout",
                str(private_key_path),
                "-out",
                str(certificate_path),
            ],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        cls.port = find_free_port()

        config_path = (
            temporary_path / "server.conf"
        )

        config_path.write_text(
            "\n".join(
                [
                    f"listen_address={HOST}",
                    f"listen_port={cls.port}",
                    f"log_file={temporary_path / 'server.log'}",
                    f"database_path={temporary_path / 'server.db'}",
                    "io_threads=2",
                    "worker_threads=2",
                    "worker_queue_capacity=32",
                    "tls_enabled=true",
                    f"tls_certificate_file={certificate_path}",
                    f"tls_private_key_file={private_key_path}",
                    "tls_handshake_timeout_seconds=2",
                    "http_max_connections=32",
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

        output_path = (
            temporary_path / "server-output.log"
        )

        cls.output_file = output_path.open(
            "w+",
            encoding="utf-8",
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

        cls.client_context = (
            ssl.create_default_context()
        )

        cls.client_context.check_hostname = False
        cls.client_context.verify_mode = (
            ssl.CERT_NONE
        )
        cls.client_context.minimum_version = (
            ssl.TLSVersion.TLSv1_2
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
            "temporary_directory",
        ):
            cls.temporary_directory.cleanup()

    @classmethod
    def server_output(cls) -> str:
        cls.output_file.flush()
        cls.output_file.seek(0)

        output = cls.output_file.read()

        cls.output_file.seek(0, 2)

        return output

    @classmethod
    def wait_until_ready(cls) -> None:
        deadline = time.monotonic() + 8

        while time.monotonic() < deadline:
            if cls.process.poll() is not None:
                raise RuntimeError(
                    "SecureCore exited during HTTPS startup.\n"
                    + cls.server_output()
                )

            try:
                status, body, _ = cls.request(
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
                ssl.SSLError,
                json.JSONDecodeError,
                http.client.HTTPException,
            ):
                pass

            time.sleep(0.05)

        raise RuntimeError(
            "SecureCore did not become HTTPS ready.\n"
            + cls.server_output()
        )

    @classmethod
    def request(
        cls,
        method: str,
        target: str,
    ) -> tuple[int, str, dict[str, str]]:
        connection = http.client.HTTPSConnection(
            HOST,
            cls.port,
            timeout=3,
            context=cls.client_context,
        )

        try:
            connection.request(
                method,
                target,
            )

            response = connection.getresponse()

            body = response.read().decode(
                "utf-8",
                errors="replace",
            )

            headers = {
                name.lower(): value
                for name, value
                in response.getheaders()
            }

            return response.status, body, headers
        finally:
            connection.close()

    def test_health_and_ready(self) -> None:
        status, body, headers = self.request(
            "GET",
            "/health",
        )

        self.assertEqual(status, 200)
        self.assertEqual(
            json.loads(body),
            {"status": "ok"},
        )
        self.assertEqual(
            headers.get("server"),
            "SecureCore",
        )

        status, body, _ = self.request(
            "GET",
            "/ready",
        )

        self.assertEqual(status, 200)
        self.assertEqual(
            json.loads(body),
            {
                "database": "ok",
                "status": "ready",
            },
        )

    def test_tls_version_is_modern(self) -> None:
        with socket.create_connection(
            (HOST, self.port),
            timeout=3,
        ) as raw_socket:
            with self.client_context.wrap_socket(
                raw_socket,
                server_hostname="localhost",
            ) as tls_socket:
                self.assertIn(
                    tls_socket.version(),
                    {"TLSv1.2", "TLSv1.3"},
                )

    def test_plain_http_is_not_accepted(self) -> None:
        with socket.create_connection(
            (HOST, self.port),
            timeout=3,
        ) as plain_socket:
            plain_socket.settimeout(3)
            plain_socket.sendall(
                b"GET /health HTTP/1.1\r\n"
                b"Host: localhost\r\n"
                b"Connection: close\r\n\r\n"
            )

            try:
                data = plain_socket.recv(1024)
            except (
                ConnectionResetError,
                socket.timeout,
            ):
                data = b""

        self.assertFalse(
            data.startswith(b"HTTP/"),
            data,
        )


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit(
            "Usage: https_smoke_test.py "
            "<secure-server> <openssl>"
        )

    SERVER_BINARY = sys.argv[1]
    OPENSSL_BINARY = sys.argv[2]

    del sys.argv[1:]

    unittest.main()
