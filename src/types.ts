export interface StorageAdapter {
  getItem(key: string): string | null | Promise<string | null>;
  setItem(key: string, value: string): void | Promise<void>;
  removeItem(key: string): void | Promise<void>;
}
export interface User { id: string; email?: string; [key: string]: unknown }
export interface Session { accessToken: string; refreshToken: string; expiresAt: number; user: User }
export interface RequestOptions { signal?: AbortSignal; timeoutMs?: number }
export interface ClientOptions {
  url: string;
  publicKey: string;
  fetch?: typeof fetch;
  storage?: StorageAdapter;
  storageNamespace?: string;
  persistSession?: boolean;
  autoRefresh?: boolean;
  oauthRedirectUrls?: readonly string[];
  webSocketFactory?: (url: string) => WebSocket;
  realtime?: { heartbeatMs?: number; reconnectDelaysMs?: readonly number[]; joinTimeoutMs?: number };
}
export interface Capabilities {
  protocol_version: number;
  runtime_version: string;
  capabilities: { auth?: boolean; database?: boolean; storage?: boolean; functions?: boolean; realtime?: boolean };
}
export class StayoError extends Error {
  constructor(message: string, readonly code = 'client_error', readonly status = 0) {
    super(message); this.name = 'StayoError';
  }
}
export class MemoryStorage implements StorageAdapter {
  private readonly values = new Map<string, string>();
  getItem(key: string): string | null { return this.values.get(key) ?? null; }
  setItem(key: string, value: string): void { this.values.set(key, value); }
  removeItem(key: string): void { this.values.delete(key); }
}
