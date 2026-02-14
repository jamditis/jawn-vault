"""Tests for the jawn-vault Python SDK."""

import json
import os
import socket
import tempfile
import threading
import unittest

from jawn_vault import (
    ConnectionError,
    CredentialResult,
    HealthResult,
    VaultClient,
    VaultError,
)


class MockVaultServer:
    """A minimal mock vault server for testing the client."""

    def __init__(self, socket_path: str):
        self.socket_path = socket_path
        self._server: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._handler = self._default_handler
        self._ready = threading.Event()

    def set_handler(self, handler):
        self._handler = handler

    def _default_handler(self, request: dict) -> dict:
        method = request["method"]
        params = request.get("params", {})

        if method == "get":
            return {
                "id": request["id"],
                "result": {
                    "value": "secret-value",
                    "cached": True,
                    "expires_at": "2025-01-01T00:00:00Z",
                },
            }
        elif method == "set":
            return {"id": request["id"], "result": {"success": True}}
        elif method == "delete":
            return {"id": request["id"], "result": {"success": True}}
        elif method == "list":
            return {
                "id": request["id"],
                "result": {"paths": ["claude/api/anthropic", "claude/api/openai"]},
            }
        elif method == "health":
            return {
                "id": request["id"],
                "result": {
                    "status": "ok",
                    "uptime_seconds": 3600,
                    "cache_entries": 5,
                    "cache_hits": 100,
                    "cache_misses": 10,
                    "cache_hit_ratio": 0.909,
                },
            }
        elif method == "invalidate":
            return {"id": request["id"], "result": {"success": True}}
        else:
            return {
                "id": request["id"],
                "error": {"code": "method_not_found", "message": f"unknown method: {method}"},
            }

    def _serve(self):
        self._server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._server.bind(self.socket_path)
        self._server.listen(1)
        self._server.settimeout(5.0)
        self._ready.set()

        try:
            conn, _ = self._server.accept()
            conn.settimeout(5.0)
            buf = b""
            while not buf.endswith(b"\n"):
                chunk = conn.recv(4096)
                if not chunk:
                    break
                buf += chunk

            if buf:
                request = json.loads(buf.decode())
                response = self._handler(request)
                conn.sendall((json.dumps(response) + "\n").encode())

            conn.close()
        except socket.timeout:
            pass
        finally:
            self._server.close()

    def start(self):
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()
        self._ready.wait(timeout=5.0)

    def wait(self):
        if self._thread:
            self._thread.join(timeout=5.0)


class TestVaultClient(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.socket_path = os.path.join(self.tmpdir, "vault.sock")

    def tearDown(self):
        try:
            os.unlink(self.socket_path)
        except FileNotFoundError:
            pass
        os.rmdir(self.tmpdir)

    def _start_server(self, handler=None):
        server = MockVaultServer(self.socket_path)
        if handler:
            server.set_handler(handler)
        server.start()
        return server

    def test_get(self):
        server = self._start_server()
        with VaultClient(socket_path=self.socket_path, token="test-token") as client:
            result = client.get("claude/api/anthropic")
            self.assertIsInstance(result, CredentialResult)
            self.assertEqual(result.value, "secret-value")
            self.assertTrue(result.cached)
        server.wait()

    def test_get_value(self):
        server = self._start_server()
        with VaultClient(socket_path=self.socket_path, token="test-token") as client:
            value = client.get_value("claude/api/anthropic")
            self.assertEqual(value, "secret-value")
        server.wait()

    def test_set(self):
        server = self._start_server()
        with VaultClient(socket_path=self.socket_path, token="test-token") as client:
            client.set("claude/api/anthropic", "new-secret")
        server.wait()

    def test_delete(self):
        server = self._start_server()
        with VaultClient(socket_path=self.socket_path, token="test-token") as client:
            client.delete("claude/api/anthropic")
        server.wait()

    def test_list(self):
        server = self._start_server()
        with VaultClient(socket_path=self.socket_path, token="test-token") as client:
            paths = client.list()
            self.assertEqual(paths, ["claude/api/anthropic", "claude/api/openai"])
        server.wait()

    def test_health(self):
        server = self._start_server()
        with VaultClient(socket_path=self.socket_path, token="test-token") as client:
            health = client.health()
            self.assertIsInstance(health, HealthResult)
            self.assertEqual(health.status, "ok")
            self.assertEqual(health.uptime_seconds, 3600)
            self.assertEqual(health.cache_entries, 5)
        server.wait()

    def test_invalidate(self):
        server = self._start_server()
        with VaultClient(socket_path=self.socket_path, token="test-token") as client:
            client.invalidate("claude/api/anthropic")
        server.wait()

    def test_error_response(self):
        def error_handler(request):
            return {
                "id": request["id"],
                "error": {"code": "not_found", "message": "credential not found"},
            }

        server = self._start_server(handler=error_handler)
        with VaultClient(socket_path=self.socket_path, token="test-token") as client:
            with self.assertRaises(VaultError) as ctx:
                client.get("nonexistent/path")
            self.assertEqual(ctx.exception.code, "not_found")
            self.assertIn("credential not found", str(ctx.exception))
        server.wait()

    def test_connection_error(self):
        with self.assertRaises(ConnectionError):
            with VaultClient(socket_path="/tmp/nonexistent.sock", token="t") as client:
                client.get("foo")

    def test_not_connected_error(self):
        client = VaultClient(socket_path=self.socket_path, token="test-token")
        with self.assertRaises(ConnectionError):
            client.get("foo")

    def test_token_from_env(self):
        os.environ["VAULT_TOKEN"] = "env-token"
        try:
            client = VaultClient(socket_path=self.socket_path)
            self.assertEqual(client.token, "env-token")
        finally:
            del os.environ["VAULT_TOKEN"]


if __name__ == "__main__":
    unittest.main()
