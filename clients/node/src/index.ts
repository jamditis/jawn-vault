/**
 * Jawn Vault Node.js SDK - Client library for the jawn-vault credential daemon.
 *
 * @example
 * ```ts
 * import { VaultClient } from "jawn-vault";
 *
 * const vault = new VaultClient();
 * await vault.connect();
 * const secret = await vault.get("claude/api/anthropic");
 * vault.close();
 * ```
 */

import { createConnection, Socket } from "net";
import { readFileSync } from "fs";
import { join } from "path";
import { homedir } from "os";

/** Error returned by the vault daemon. */
export class VaultError extends Error {
  readonly code: string;

  constructor(message: string, code: string = "unknown") {
    super(message);
    this.name = "VaultError";
    this.code = code;
  }
}

/** Error connecting to the vault daemon. */
export class ConnectionError extends VaultError {
  constructor(message: string) {
    super(message, "connection_error");
    this.name = "ConnectionError";
  }
}

/** Result of a credential retrieval. */
export interface CredentialResult {
  value: string;
  cached: boolean;
  expires_at?: string;
}

/** Result of a health check. */
export interface HealthResult {
  status: string;
  uptime_seconds: number;
  cache_entries: number;
  cache_hits: number;
  cache_misses: number;
  cache_hit_ratio: number;
}

interface VaultRequest {
  id: string;
  auth: string;
  method: string;
  params: Record<string, unknown>;
}

interface VaultResponse {
  id: string;
  result?: Record<string, unknown>;
  error?: { code: string; message: string };
}

export interface VaultClientOptions {
  /** Path to the Unix socket. Defaults to $VAULT_SOCKET or $XDG_RUNTIME_DIR/jawn-vault.sock. */
  socketPath?: string;
  /** Auth token. Defaults to $VAULT_TOKEN or contents of ~/.vault-token. */
  token?: string;
  /** Connection/read timeout in milliseconds. Defaults to 30000. */
  timeoutMs?: number;
}

function resolveToken(): string {
  const envToken = process.env.VAULT_TOKEN;
  if (envToken) return envToken;

  const tokenPath = join(homedir(), ".vault-token");
  try {
    return readFileSync(tokenPath, "utf-8").trim();
  } catch {
    return "";
  }
}

function resolveSocketPath(): string {
  if (process.env.VAULT_SOCKET) return process.env.VAULT_SOCKET;
  const runtime = process.env.XDG_RUNTIME_DIR ?? "/tmp";
  return join(runtime, "jawn-vault.sock");
}

export class VaultClient {
  private readonly socketPath: string;
  private readonly token: string;
  private readonly timeoutMs: number;
  private socket: Socket | null = null;
  private requestId = 0;

  constructor(options: VaultClientOptions = {}) {
    this.socketPath = options.socketPath ?? resolveSocketPath();
    this.token = options.token ?? resolveToken();
    this.timeoutMs = options.timeoutMs ?? 30_000;
  }

  /** Open the Unix socket connection. */
  connect(): Promise<void> {
    return new Promise((resolve, reject) => {
      const sock = createConnection(this.socketPath);
      sock.setTimeout(this.timeoutMs);

      sock.once("connect", () => {
        this.socket = sock;
        resolve();
      });

      sock.once("error", (err: Error) => {
        reject(
          new ConnectionError(
            `failed to connect to vault at ${this.socketPath}: ${err.message}`
          )
        );
      });
    });
  }

  /** Close the connection. */
  close(): void {
    if (this.socket) {
      this.socket.destroy();
      this.socket = null;
    }
  }

  private send(method: string, params: Record<string, unknown> = {}): Promise<VaultResponse> {
    return new Promise((resolve, reject) => {
      if (!this.socket) {
        reject(new ConnectionError("not connected - call connect() first"));
        return;
      }

      this.requestId++;
      const request: VaultRequest = {
        id: `node-${this.requestId}`,
        auth: this.token,
        method,
        params: Object.fromEntries(
          Object.entries(params).filter(([, v]) => v !== undefined && v !== null)
        ),
      };

      const payload = JSON.stringify(request) + "\n";
      let buffer = "";

      const onData = (chunk: Buffer) => {
        buffer += chunk.toString();
        if (buffer.includes("\n")) {
          cleanup();
          try {
            const response: VaultResponse = JSON.parse(buffer.trim());
            if (response.error) {
              reject(new VaultError(response.error.message, response.error.code));
            } else {
              resolve(response);
            }
          } catch (err) {
            reject(new VaultError(`invalid response: ${err}`));
          }
        }
      };

      const onError = (err: Error) => {
        cleanup();
        reject(new ConnectionError(`socket error: ${err.message}`));
      };

      const onTimeout = () => {
        cleanup();
        reject(new ConnectionError("request timed out"));
      };

      const cleanup = () => {
        this.socket?.off("data", onData);
        this.socket?.off("error", onError);
        this.socket?.off("timeout", onTimeout);
      };

      this.socket.on("data", onData);
      this.socket.once("error", onError);
      this.socket.once("timeout", onTimeout);
      this.socket.write(payload);
    });
  }

  /**
   * Retrieve a credential by path.
   * @param path - Credential path (e.g. "claude/api/anthropic")
   * @param ttlSeconds - Optional custom cache TTL
   */
  async get(path: string, ttlSeconds?: number): Promise<CredentialResult> {
    const resp = await this.send("get", { path, ttl_seconds: ttlSeconds });
    const r = resp.result as Record<string, unknown>;
    return {
      value: r.value as string,
      cached: r.cached as boolean,
      expires_at: r.expires_at as string | undefined,
    };
  }

  /**
   * Convenience method - retrieve just the credential string.
   * @param path - Credential path
   */
  async getValue(path: string): Promise<string> {
    return (await this.get(path)).value;
  }

  /**
   * Store a credential.
   * @param path - Credential path
   * @param value - Secret value to store
   * @param ttlSeconds - Optional custom cache TTL
   */
  async set(path: string, value: string, ttlSeconds?: number): Promise<void> {
    await this.send("set", { path, value, ttl_seconds: ttlSeconds });
  }

  /**
   * Delete a credential.
   * @param path - Credential path
   */
  async delete(path: string): Promise<void> {
    await this.send("delete", { path });
  }

  /**
   * List credential paths under a prefix.
   * @param prefix - Optional path prefix to filter by
   */
  async list(prefix?: string): Promise<string[]> {
    const resp = await this.send("list", { prefix });
    return (resp.result as Record<string, unknown>).paths as string[];
  }

  /** Check daemon health and cache statistics. */
  async health(): Promise<HealthResult> {
    const resp = await this.send("health");
    const r = resp.result as Record<string, unknown>;
    return {
      status: r.status as string,
      uptime_seconds: r.uptime_seconds as number,
      cache_entries: r.cache_entries as number,
      cache_hits: r.cache_hits as number,
      cache_misses: r.cache_misses as number,
      cache_hit_ratio: r.cache_hit_ratio as number,
    };
  }

  /**
   * Invalidate a cache entry.
   * @param path - Credential path to invalidate
   */
  async invalidate(path: string): Promise<void> {
    await this.send("invalidate", { path });
  }
}
