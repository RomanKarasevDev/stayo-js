import { StayoError, type ClientOptions, type RequestOptions } from './types.js';

export function projectOrigin(value: string): string {
  let u: URL;
  try { u = new URL(value); } catch { throw new StayoError('A valid project origin is required.', 'invalid_url'); }
  const local = ['localhost', '127.0.0.1', '[::1]'].includes(u.hostname);
  if ((u.protocol !== 'https:' && !(local && u.protocol === 'http:')) || u.username || u.password || u.search || u.hash || u.pathname !== '/') {
    throw new StayoError('Use an HTTPS project origin, or HTTP on loopback for development.', 'invalid_url');
  }
  return u.origin;
}
export function publicKey(value: string): string {
  if (!value || value.length > 16384 || /[\s\x00-\x1f\x7f]/.test(value) || /^(sb_secret_|service_role|secret_)/i.test(value)) {
    throw new StayoError('A public application key is required.', 'invalid_public_key');
  }
  const payload = value.split('.')[1];
  if (payload) {
    try {
      const decoded = JSON.parse(atob(payload.replace(/-/g, '+').replace(/_/g, '/')));
      if (decoded.role === 'service_role' || decoded.role === 'supabase_admin' || decoded.role === 'postgres') {
        throw new StayoError('Privileged keys cannot be used in a public client.', 'invalid_public_key');
      }
    } catch (e) { if (e instanceof StayoError) throw e; }
  }
  return value;
}
export function identifier(value: string): string {
  if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(value)) throw new StayoError('Invalid identifier.', 'invalid_identifier');
  return value;
}
export function objectPath(value: string): string {
  const segments = value.split('/');
  if (segments.some(s => !s || s === '.' || s === '..' || /[\\\x00-\x1f\x7f]/.test(s))) throw new StayoError('Invalid object path.', 'invalid_path');
  return segments.map(encodeURIComponent).join('/');
}
export function bucketName(value: string): string {
  if (!/^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(value) || value === '..') throw new StayoError('Invalid bucket name.', 'invalid_path');
  return encodeURIComponent(value);
}
export function functionName(value: string): string {
  if (!/^[a-zA-Z][a-zA-Z0-9_-]{0,127}$/.test(value)) throw new StayoError('Invalid function name.', 'invalid_identifier');
  return value;
}
export interface HTTPOptions extends RequestOptions {
  method?: string;
  body?: unknown;
  rawBody?: BodyInit;
  headers?: Record<string, string>;
  token?: string | null;
  anonymous?: boolean;
}
export class HTTP {
  readonly origin: string;
  readonly key: string;
  readonly fetcher: typeof fetch;
  getToken: () => Promise<string | null> = async () => null;
  // Changes when the signed-in account changes or the client signs out, not
  // on refresh or a failed sign-in attempt. A response to a request that used
  // an earlier identity is rejected.
  getAuthGeneration: () => number = () => 0;
  private disposed = false;
  dispose(): void { this.disposed = true; }
  constructor(options: ClientOptions) {
    this.origin = projectOrigin(options.url); this.key = publicKey(options.publicKey);
    this.fetcher = options.fetch ?? globalThis.fetch.bind(globalThis);
  }
  async request(path: string, opts: HTTPOptions = {}): Promise<Response> {
    if (this.disposed) throw new StayoError('Client has been disposed.', 'client_disposed');
    const u = new URL(path, this.origin);
    if (u.origin !== this.origin || !path.startsWith('/') || path.startsWith('//')) throw new StayoError('Request must stay on the project origin.', 'invalid_url');
    if (opts.signal?.aborted) throw new StayoError('Request canceled or timed out.', 'aborted');
    const bound = opts.token === undefined && !opts.anonymous;
    const generation = this.getAuthGeneration();
    const superseded = () => bound && generation !== this.getAuthGeneration();
    const token = opts.token !== undefined ? opts.token : opts.anonymous ? null : await this.getToken();
    if (superseded()) throw new StayoError('Auth operation superseded.', 'auth_superseded');
    const h = new Headers(opts.headers);
    h.set('apikey', this.key); h.set('Authorization', `Bearer ${token ?? this.key}`);
    let body = opts.rawBody;
    if (opts.body !== undefined) {
      try { body = JSON.stringify(opts.body); } catch { throw new StayoError('Request body must be JSON serializable.', 'invalid_body'); }
      h.set('Content-Type', 'application/json');
    }
    const timeoutMs = opts.timeoutMs ?? 30000;
    if (!Number.isFinite(timeoutMs) || timeoutMs <= 0) throw new StayoError('Invalid request timeout.', 'invalid_timeout');
    const controller = new AbortController();
    const abort = () => controller.abort();
    if (opts.signal?.aborted) controller.abort();
    opts.signal?.addEventListener('abort', abort, { once: true });
    const timeout = setTimeout(abort, timeoutMs);
    try {
      const response = await this.fetcher(u, {method: opts.method ?? 'GET', headers: h, ...(body === undefined ? {} : {body}), signal: controller.signal, redirect: 'error', credentials: 'omit', cache: 'no-store'});
      if (response.url && new URL(response.url).origin !== this.origin) throw new StayoError('Cross-origin response rejected.', 'invalid_redirect');
      if (superseded()) throw new StayoError('Auth operation superseded.', 'auth_superseded');
      if (!response.ok) {
        const parsed = await response.json().catch(() => null) as Record<string, unknown> | null;
        const nested = parsed?.error;
        const candidate = parsed?.code ?? parsed?.error_code ??
          (nested && typeof nested === 'object' && !Array.isArray(nested) ? (nested as Record<string, unknown>).code : undefined);
        const code = typeof candidate === 'string' && /^[A-Za-z][A-Za-z0-9_]{0,63}$/.test(candidate) ? candidate : 'http_error';
        // Never retain server messages: providers can echo request bodies or credentials.
        throw new StayoError(`Project request failed (HTTP ${response.status}).`, code, response.status);
      }
      // Read under the same deadline/signal, including slow response bodies.
      const bytes = response.status === 204 || response.status === 205 ? null : await response.arrayBuffer();
      // The server may already have applied a mutation; it is never retried.
      if (superseded()) throw new StayoError('Auth operation superseded.', 'auth_superseded');
      return new Response(bytes, {status: response.status, statusText: response.statusText, headers: response.headers});
    } catch (error) {
      if (error instanceof StayoError) throw error;
      if (controller.signal.aborted) throw new StayoError('Request canceled or timed out.', 'aborted');
      throw new StayoError('Project request failed. Check connectivity and redirects.', 'network_error');
    } finally { clearTimeout(timeout); opts.signal?.removeEventListener('abort', abort); }
  }
  async json<T>(path: string, opts: HTTPOptions = {}): Promise<T> {
    const res = await this.request(path, opts);
    if (res.status === 204 || res.headers.get('Content-Length') === '0') return null as T;
    try { return await res.json() as T; } catch { throw new StayoError('Invalid project response.', 'invalid_response', res.status); }
  }
}
