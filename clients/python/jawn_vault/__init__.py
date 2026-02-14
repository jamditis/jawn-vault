"""Jawn Vault Python SDK - Client library for the jawn-vault credential daemon."""

import json
import os
import socket
from dataclasses import dataclass
from typing import Optional


class VaultError(Exception):
    """Error returned by the vault daemon."""

    def __init__(self, message: str, code: str = "unknown"):
        super().__init__(message)
        self.code = code


class ConnectionError(VaultError):
    """Failed to connect to the vault daemon."""

    def __init__(self, message: str):
        super().__init__(message, code="connection_error")


@dataclass
class CredentialResult:
    """Result of a credential retrieval."""

    value: str
    cached: bool
    expires_at: Optional[str] = None


@dataclass
class HealthResult:
    """Result of a health check."""

    status: str
    uptime_seconds: int
    cache_entries: int
    cache_hits: int
    cache_misses: int
    cache_hit_ratio: float


class VaultClient:
    """Client for interacting with the jawn-vault daemon over a Unix socket.

    Can be used as a context manager::

        with VaultClient() as vault:
            secret = vault.get("claude/api/anthropic")

    Or managed manually::

        vault = VaultClient()
        vault.connect()
        secret = vault.get("claude/api/anthropic")
        vault.close()
    """

    def __init__(
        self,
        socket_path: Optional[str] = None,
        token: Optional[str] = None,
        timeout: float = 30.0,
    ):
        self.socket_path = socket_path or os.environ.get(
            "VAULT_SOCKET",
            os.path.join(
                os.environ.get("XDG_RUNTIME_DIR", "/tmp"),
                "jawn-vault.sock",
            ),
        )
        self.token = token or self._resolve_token()
        self.timeout = timeout
        self._socket: Optional[socket.socket] = None
        self._request_id = 0

    @staticmethod
    def _resolve_token() -> str:
        """Resolve the auth token from environment or token file."""
        env_token = os.environ.get("VAULT_TOKEN")
        if env_token:
            return env_token

        token_path = os.path.join(os.path.expanduser("~"), ".vault-token")
        try:
            with open(token_path) as f:
                return f.read().strip()
        except FileNotFoundError:
            return ""

    def connect(self) -> "VaultClient":
        """Open the Unix socket connection."""
        self._socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._socket.settimeout(self.timeout)
        try:
            self._socket.connect(self.socket_path)
        except (OSError, socket.error) as exc:
            self._socket.close()
            self._socket = None
            raise ConnectionError(
                f"failed to connect to vault at {self.socket_path}: {exc}"
            ) from exc
        return self

    def close(self) -> None:
        """Close the connection."""
        if self._socket:
            self._socket.close()
            self._socket = None

    def __enter__(self) -> "VaultClient":
        return self.connect()

    def __exit__(self, *args: object) -> None:
        self.close()

    def _send(self, method: str, **params: object) -> dict:
        """Send a request and return the parsed response."""
        if self._socket is None:
            raise ConnectionError("not connected - use connect() or a context manager")

        self._request_id += 1
        request = {
            "id": f"py-{self._request_id}",
            "auth": self.token,
            "method": method,
            "params": {k: v for k, v in params.items() if v is not None},
        }

        payload = json.dumps(request) + "\n"
        self._socket.sendall(payload.encode())

        # Read until we get a complete newline-delimited JSON response
        buf = b""
        while not buf.endswith(b"\n"):
            chunk = self._socket.recv(4096)
            if not chunk:
                raise ConnectionError("connection closed by daemon")
            buf += chunk

        response = json.loads(buf.decode())

        if "error" in response and response["error"] is not None:
            err = response["error"]
            raise VaultError(err.get("message", "unknown error"), err.get("code", "unknown"))

        return response

    def get(self, path: str, ttl_seconds: Optional[int] = None) -> CredentialResult:
        """Retrieve a credential by path.

        Args:
            path: Credential path (e.g. "claude/api/anthropic").
            ttl_seconds: Optional custom cache TTL.

        Returns:
            CredentialResult with the secret value and cache metadata.

        Raises:
            VaultError: If the credential is not found or access is denied.
        """
        resp = self._send("get", path=path, ttl_seconds=ttl_seconds)
        result = resp["result"]
        return CredentialResult(
            value=result["value"],
            cached=result.get("cached", False),
            expires_at=result.get("expires_at"),
        )

    def get_value(self, path: str) -> str:
        """Convenience method - retrieve just the credential string.

        Args:
            path: Credential path.

        Returns:
            The secret value as a string.
        """
        return self.get(path).value

    def set(self, path: str, value: str, ttl_seconds: Optional[int] = None) -> None:
        """Store a credential.

        Args:
            path: Credential path.
            value: Secret value to store.
            ttl_seconds: Optional custom cache TTL.

        Raises:
            VaultError: If access is denied or backend fails.
        """
        self._send("set", path=path, value=value, ttl_seconds=ttl_seconds)

    def delete(self, path: str) -> None:
        """Delete a credential.

        Args:
            path: Credential path.

        Raises:
            VaultError: If the credential is not found or access is denied.
        """
        self._send("delete", path=path)

    def list(self, prefix: Optional[str] = None) -> list[str]:
        """List credential paths under a prefix.

        Args:
            prefix: Optional path prefix to filter by.

        Returns:
            List of credential paths.
        """
        resp = self._send("list", prefix=prefix)
        return resp["result"]["paths"]

    def health(self) -> HealthResult:
        """Check daemon health and cache statistics.

        Returns:
            HealthResult with daemon status and cache stats.
        """
        resp = self._send("health")
        r = resp["result"]
        return HealthResult(
            status=r["status"],
            uptime_seconds=r["uptime_seconds"],
            cache_entries=r["cache_entries"],
            cache_hits=r["cache_hits"],
            cache_misses=r["cache_misses"],
            cache_hit_ratio=r["cache_hit_ratio"],
        )

    def invalidate(self, path: str) -> None:
        """Invalidate a cache entry.

        Args:
            path: Credential path to invalidate from cache.
        """
        self._send("invalidate", path=path)
