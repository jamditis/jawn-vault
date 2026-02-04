# Jawn Vault roadmap

## Current status: Phase 1 complete

The core infrastructure is implemented:
- Unix socket server with tokio
- Pass backend integration
- In-memory cache with TTL and secure memory
- Client authentication with SQLite
- Audit logging with SQLite
- CLI tool for basic operations

## Phase 2: Security hardening (next)

| Task | Status | Notes |
|------|--------|-------|
| SO_PEERCRED verification | ✓ Done | Logs PID/UID of connecting process |
| Token hashing | ✓ Done | SHA-256 in SQLite |
| Permission model | ✓ Done | Path patterns with read/write/admin |
| Audit logging | ✓ Done | SQLite with retention |
| systemd hardening | ✓ Done | NoNewPrivileges, ProtectSystem, etc. |

## Phase 3: Client libraries

| Task | Status | Notes |
|------|--------|-------|
| Python SDK | Pending | Unix socket, error handling |
| Node.js SDK | Pending | TypeScript, same pattern |
| CLI tool | ✓ Done | get/set/list/health/token |
| Documentation | ✓ Done | README, example config |

### Python SDK design

```python
# clients/python/jawn_vault/__init__.py
import socket
import json
import os
from typing import Optional
from contextlib import contextmanager

class VaultClient:
    def __init__(
        self,
        socket_path: Optional[str] = None,
        token: Optional[str] = None,
    ):
        self.socket_path = socket_path or os.environ.get(
            'VAULT_SOCKET',
            f"/run/user/{os.getuid()}/jawn-vault.sock"
        )
        self.token = token or os.environ.get('VAULT_TOKEN', '')
        self._socket = None
        self._request_id = 0

    def __enter__(self):
        self._socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._socket.connect(self.socket_path)
        return self

    def __exit__(self, *args):
        if self._socket:
            self._socket.close()

    def _request(self, method: str, **params) -> dict:
        self._request_id += 1
        request = {
            'id': f'py-{self._request_id}',
            'auth': self.token,
            'method': method,
            'params': {k: v for k, v in params.items() if v is not None}
        }
        self._socket.send((json.dumps(request) + '\n').encode())
        response = b''
        while not response.endswith(b'\n'):
            response += self._socket.recv(4096)
        return json.loads(response.decode())

    def get(self, path: str) -> str:
        resp = self._request('get', path=path)
        if 'error' in resp:
            raise VaultError(resp['error']['message'])
        return resp['result']['value']

    def set(self, path: str, value: str) -> None:
        resp = self._request('set', path=path, value=value)
        if 'error' in resp:
            raise VaultError(resp['error']['message'])

    def list(self, prefix: Optional[str] = None) -> list[str]:
        resp = self._request('list', prefix=prefix)
        if 'error' in resp:
            raise VaultError(resp['error']['message'])
        return resp['result']['paths']

class VaultError(Exception):
    pass
```

## Phase 4: Token rotation (future)

| Task | Status | Notes |
|------|--------|-------|
| Rotation scheduler | Pending | tokio-cron-scheduler |
| Provider trait | ✓ Stub | In rotation/mod.rs |
| Slack OAuth | Pending | 12h tokens |
| Google OAuth | Pending | 1h tokens |
| Telegram alerts | Pending | On rotation failure |

### Slack rotation implementation

```rust
// Future: src/rotation/slack.rs
pub struct SlackOAuthProvider {
    client_id: String,
    client_secret: String,
    refresh_token_path: String,
    access_token_path: String,
}

#[async_trait]
impl RotationProvider for SlackOAuthProvider {
    fn name(&self) -> &str { "slack" }
    fn paths(&self) -> &[String] { &[self.access_token_path.clone()] }

    async fn rotate(&self) -> Result<String, RotationError> {
        let refresh_token = backend.get(&self.refresh_token_path).await?;

        let client = reqwest::Client::new();
        let resp = client
            .post("https://slack.com/api/oauth.v2.access")
            .form(&[
                ("grant_type", "refresh_token"),
                ("client_id", &self.client_id),
                ("client_secret", &self.client_secret),
                ("refresh_token", &refresh_token),
            ])
            .send()
            .await
            .map_err(|e| RotationError::Http(e.to_string()))?;

        let json: SlackTokenResponse = resp.json().await?;
        Ok(json.access_token)
    }
}
```

## Phase 5: Service migration

| Service | Status | Notes |
|---------|--------|-------|
| houseofjawn-bot | Pending | Replace os.getenv |
| notify-service | Pending | Same pattern |
| houseofjawn-dashboard | Pending | Multiple tokens |
| student-tracker | Pending | Canvas token |

### Migration pattern

**Before:**
```python
# In systemd unit
EnvironmentFile=/home/jamditis/.claude/.env

# In code
token = os.environ.get('TELEGRAM_BOT_TOKEN')
```

**After:**
```python
from jawn_vault import VaultClient

with VaultClient() as vault:
    token = vault.get('claude/tokens/telegram-bot')
```

## Phase 6: Polish

| Task | Status | Notes |
|------|--------|-------|
| Dashboard widget | Pending | Optional vault status |
| Telegram /vault cmd | Pending | Status, recent access |
| Performance tuning | Pending | Profiling |
| Operations runbook | Pending | Troubleshooting docs |

## Testing strategy

### Unit tests (in code)
- Cache TTL behavior
- Pattern matching
- Token validation
- Protocol serialization

### Integration tests
Run with `cargo test -- --ignored` (requires pass):
- Backend credential retrieval
- Full request/response cycle
- Authentication enforcement

### E2E tests
Shell script in `tests/e2e/`:
```bash
#!/bin/bash
# tests/e2e/test_basic.sh

# Start daemon in background
./target/release/jawn-vault &
VAULT_PID=$!
sleep 1

# Create client
TOKEN=$(./target/release/vault-cli token create test --grant '**' -p admin)

# Test operations
export VAULT_TOKEN="$TOKEN"
./target/release/vault-cli health
./target/release/vault-cli list claude/
./target/release/vault-cli get claude/api/anthropic

# Cleanup
kill $VAULT_PID
```

## Performance targets

| Operation | Target | Measured |
|-----------|--------|----------|
| Cache hit | <5ms | TBD |
| Cache miss (pass) | <150ms | TBD |
| Authentication | <1ms | TBD |
| Audit log write | <5ms | TBD |

## Build and deploy

```bash
# Build for release
cargo build --release

# Install systemd service
sudo cp deploy/jawn-vault.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable jawn-vault
sudo systemctl start jawn-vault

# Check status
sudo systemctl status jawn-vault
journalctl -u jawn-vault -f
```
