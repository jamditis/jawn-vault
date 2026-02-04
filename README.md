# Jawn Vault

Secure credential proxy for the houseofjawn ecosystem. Wraps the existing `pass` password store with caching, audit logging, and automatic token rotation.

## Features

- **Fast caching** — Sub-5ms retrieval for cached credentials (vs ~128ms for raw GPG decryption)
- **Unix socket API** — No network exposure, kernel-enforced access control
- **Audit logging** — Full trail of who accessed what credential, when
- **Memory safety** — Secrets zeroed on drop, no accidental logging
- **Client authentication** — Bearer tokens with path-based permissions

## Quick start

```bash
# Build
cargo build --release

# Create data directories
mkdir -p ~/.local/share/jawn-vault
mkdir -p ~/.config/jawn-vault

# Start the daemon
./target/release/jawn-vault

# Create a client token
./target/release/vault-cli token create houseofjawn-bot \
  --grant 'claude/**' --permission read

# Use the token
export VAULT_TOKEN='vault_abc123...'
./target/release/vault-cli get claude/api/anthropic
```

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                       JAWN VAULT DAEMON                         │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │ Unix Socket API (/run/user/1000/jawn-vault.sock)          │  │
│  └───────────────────────────────────────────────────────────┘  │
│                              │                                   │
│  ┌───────────────┐  ┌───────────────┐  ┌───────────────────┐   │
│  │ Cache Layer   │  │ Pass Backend  │  │ Audit Log         │   │
│  │ (in-memory)   │  │ (gpg decrypt) │  │ (SQLite)          │   │
│  │ SecretBox     │  │ subprocess    │  │                   │   │
│  └───────────────┘  └───────────────┘  └───────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

## Configuration

Configuration file: `~/.config/jawn-vault/config.toml`

```toml
[server]
socket_path = "/run/user/1000/jawn-vault.sock"
socket_mode = 384  # 0o600 in decimal
max_connections = 100

[cache]
enabled = true
default_ttl_secs = 300  # 5 minutes
max_ttl_secs = 3600     # 1 hour
max_entries = 1000

[pass]
binary = "pass"
store_path = "/home/jamditis/.password-store"
timeout_secs = 10

[audit]
enabled = true
db_path = "/home/jamditis/.local/share/jawn-vault/audit.db"
retention_days = 90
```

## CLI usage

```bash
# Get a credential
vault-cli get claude/api/anthropic

# Set a credential (from stdin)
echo "new-value" | vault-cli set claude/api/newkey

# List credentials
vault-cli list claude/

# Check daemon health
vault-cli health

# Invalidate cache entry
vault-cli invalidate claude/api/anthropic

# Token management
vault-cli token create myapp --grant 'claude/**' --permission read
vault-cli token list
vault-cli token revoke <client-id>
```

## API protocol

Newline-delimited JSON over Unix socket.

**Request:**
```json
{
  "id": "req-12345",
  "auth": "vault_abc123...",
  "method": "get",
  "params": {"path": "claude/api/anthropic"}
}
```

**Response:**
```json
{
  "id": "req-12345",
  "result": {
    "value": "sk-ant-api03-...",
    "cached": true,
    "expires_at": "2024-01-15T12:30:00Z"
  }
}
```

**Methods:** `get`, `set`, `delete`, `list`, `health`, `rotate`, `invalidate`

## Client libraries

### Python

```python
from jawn_vault import VaultClient

with VaultClient() as vault:
    api_key = vault.get("claude/api/anthropic")
```

### Node.js

```javascript
import { VaultClient } from '@jawn/vault';

const vault = new VaultClient();
const apiKey = await vault.get('claude/api/anthropic');
```

## Security

- **Socket permissions** — Default mode 0600, only owner can connect
- **SO_PEERCRED** — Audit logs include connecting process PID/UID
- **Token hashing** — Tokens stored as SHA-256 hashes, not plaintext
- **Secret memory** — Uses `secrecy` crate to prevent accidental exposure
- **Zeroization** — All secrets overwritten on drop

## Development

```bash
# Run tests
cargo test

# Run with debug logging
RUST_LOG=jawn_vault=debug cargo run

# Run integration tests (requires pass configured)
cargo test -- --ignored
```

## License

MIT
