/**
 * Tests for the jawn-vault Node.js SDK.
 *
 * Uses Node.js built-in test runner (node --test) and a mock Unix socket server.
 */

import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import { createServer, Server, Socket } from "net";
import { mkdtempSync, rmSync, unlinkSync } from "fs";
import { join } from "path";
import { tmpdir } from "os";

import { VaultClient, VaultError, ConnectionError } from "../index.js";

function createMockServer(
  socketPath: string,
  handler?: (request: Record<string, unknown>) => Record<string, unknown>
): Server {
  const defaultHandler = (request: Record<string, unknown>) => {
    const method = request.method as string;
    const id = request.id as string;

    switch (method) {
      case "get":
        return {
          id,
          result: {
            value: "secret-value",
            cached: true,
            expires_at: "2025-01-01T00:00:00Z",
          },
        };
      case "set":
      case "delete":
      case "invalidate":
        return { id, result: { success: true } };
      case "list":
        return {
          id,
          result: { paths: ["claude/api/anthropic", "claude/api/openai"] },
        };
      case "health":
        return {
          id,
          result: {
            status: "ok",
            uptime_seconds: 3600,
            cache_entries: 5,
            cache_hits: 100,
            cache_misses: 10,
            cache_hit_ratio: 0.909,
          },
        };
      default:
        return {
          id,
          error: { code: "method_not_found", message: `unknown method: ${method}` },
        };
    }
  };

  const h = handler ?? defaultHandler;

  const server = createServer((conn: Socket) => {
    let buf = "";
    conn.on("data", (chunk: Buffer) => {
      buf += chunk.toString();
      if (buf.includes("\n")) {
        const request = JSON.parse(buf.trim());
        const response = h(request);
        conn.write(JSON.stringify(response) + "\n");
      }
    });
  });

  server.listen(socketPath);
  return server;
}

describe("VaultClient", () => {
  let tmpDir: string;
  let socketPath: string;
  let server: Server;

  before(() => {
    tmpDir = mkdtempSync(join(tmpdir(), "vault-test-"));
    socketPath = join(tmpDir, "vault.sock");
    server = createMockServer(socketPath);
  });

  after(() => {
    server.close();
    try { unlinkSync(socketPath); } catch {}
    try { rmSync(tmpDir, { recursive: true }); } catch {}
  });

  it("should get a credential", async () => {
    const client = new VaultClient({ socketPath, token: "test-token" });
    await client.connect();
    const result = await client.get("claude/api/anthropic");
    assert.equal(result.value, "secret-value");
    assert.equal(result.cached, true);
    client.close();
  });

  it("should get just the value string", async () => {
    const client = new VaultClient({ socketPath, token: "test-token" });
    await client.connect();
    const value = await client.getValue("claude/api/anthropic");
    assert.equal(value, "secret-value");
    client.close();
  });

  it("should set a credential", async () => {
    const client = new VaultClient({ socketPath, token: "test-token" });
    await client.connect();
    await client.set("claude/api/anthropic", "new-secret");
    client.close();
  });

  it("should delete a credential", async () => {
    const client = new VaultClient({ socketPath, token: "test-token" });
    await client.connect();
    await client.delete("claude/api/anthropic");
    client.close();
  });

  it("should list credentials", async () => {
    const client = new VaultClient({ socketPath, token: "test-token" });
    await client.connect();
    const paths = await client.list();
    assert.deepEqual(paths, ["claude/api/anthropic", "claude/api/openai"]);
    client.close();
  });

  it("should check health", async () => {
    const client = new VaultClient({ socketPath, token: "test-token" });
    await client.connect();
    const health = await client.health();
    assert.equal(health.status, "ok");
    assert.equal(health.uptime_seconds, 3600);
    assert.equal(health.cache_entries, 5);
    client.close();
  });

  it("should invalidate a cache entry", async () => {
    const client = new VaultClient({ socketPath, token: "test-token" });
    await client.connect();
    await client.invalidate("claude/api/anthropic");
    client.close();
  });

  it("should throw ConnectionError when not connected", async () => {
    const client = new VaultClient({ socketPath, token: "test-token" });
    await assert.rejects(() => client.get("foo"), ConnectionError);
  });

  it("should throw ConnectionError for bad socket path", async () => {
    const client = new VaultClient({
      socketPath: "/tmp/nonexistent.sock",
      token: "test-token",
    });
    await assert.rejects(() => client.connect(), ConnectionError);
  });
});

describe("VaultClient error handling", () => {
  let tmpDir: string;
  let socketPath: string;
  let server: Server;

  before(() => {
    tmpDir = mkdtempSync(join(tmpdir(), "vault-test-err-"));
    socketPath = join(tmpDir, "vault.sock");
    server = createMockServer(socketPath, (request) => ({
      id: request.id as string,
      error: { code: "not_found", message: "credential not found" },
    }));
  });

  after(() => {
    server.close();
    try { unlinkSync(socketPath); } catch {}
    try { rmSync(tmpDir, { recursive: true }); } catch {}
  });

  it("should throw VaultError on error response", async () => {
    const client = new VaultClient({ socketPath, token: "test-token" });
    await client.connect();
    await assert.rejects(
      () => client.get("nonexistent/path"),
      (err: Error) => {
        assert.ok(err instanceof VaultError);
        assert.equal((err as VaultError).code, "not_found");
        assert.match(err.message, /credential not found/);
        return true;
      }
    );
    client.close();
  });
});
