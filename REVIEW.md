# Jawn Vault Code Review

Review of changes introduced in commits `163e64d`..`105fabc` (Phases 1–4).

## Critical

### 1. SSRF risk in HTTP rotation provider
**Location:** `src/rotation/http.rs:87-91`

The generic HTTP provider posts to an arbitrary URL from config with no
validation. A misconfigured or malicious config could target internal services
(localhost, cloud metadata endpoints, etc.).

**Recommendation:** Add URL validation — reject `localhost`, `127.0.0.1`,
private IP ranges, and link-local addresses. Consider an allowlist of domains.

### 2. Hardcoded user paths in fallback config
**Locations:**
- `src/main.rs:97`
- `src/config.rs:179, 192, 225`

Fallback paths are hardcoded to `/home/jamditis/` instead of resolving via the
`dirs` crate (which is already a dependency).

**Recommendation:** Replace with `dirs::home_dir()` or `dirs::config_dir()`.

### 3. Panic-prone mutex handling
**Locations:**
- `src/alerting/mod.rs:90`
- `src/auth/mod.rs:211, 355, 364`
- `src/audit/mod.rs:102, 147, 186, 226, 266, 314`

Multiple `.unwrap()` / `.expect()` calls on `Mutex::lock()`. A poisoned lock
(caused by a panic in another thread) will crash the process.

**Recommendation:** Use `.lock().map_err()` or a poison-recovery pattern.

## High

### 4. Unbounded message buffering in client SDKs
**Locations:**
- `clients/python/jawn_vault/__init__.py:138-142`
- `clients/node/src/index.ts:159`

Neither client enforces a maximum response size. A misbehaving daemon could
cause memory exhaustion on the client side.

**Recommendation:** Cap buffer accumulation (e.g., 1 MB for Python, 10 MB for
Node.js) and raise an error if exceeded.

### 5. No HTTP timeout on rotation requests
**Location:** `src/rotation/http.rs`, `src/rotation/slack.rs`,
`src/rotation/google.rs`

`reqwest` calls lack explicit timeouts. A hanging token endpoint blocks the
rotation scheduler indefinitely.

**Recommendation:** Set a request timeout (e.g., 30 s) via
`reqwest::ClientBuilder::timeout()`.

## Medium

### 6. Rotation trigger is stubbed out
**Location:** `src/server/mod.rs:336`

The `rotate` API endpoint only invalidates the cache with a
`// TODO: Implement rotation trigger` comment. Manual rotation via the API does
not actually invoke any provider.

### 7. Telegram rate-limit interval is hardcoded
**Location:** `src/alerting/mod.rs`

The 60-second minimum interval between alerts is not configurable.

### 8. No request size limit on the server
**Location:** `src/server/mod.rs:142-144`

`read_line()` has no upper bound on line length, allowing a client to send an
arbitrarily large request.

## Positive findings

- Proper use of `secrecy::SecretString` and `zeroize` for secret memory safety
- TLS via `rustls` (not OpenSSL)
- Solid test suites in both client SDKs (11 Python, 10 Node.js tests)
- SQLite audit logging with configurable retention
- Well-maintained `ROADMAP.md` — all Phase 4 items checked off
