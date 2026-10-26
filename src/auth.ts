import { HTTP } from './http.js';
import { MemoryStorage, StayoError, type ClientOptions, type RequestOptions, type Session, type StorageAdapter, type User } from './types.js';
export type AuthEvent = 'SIGNED_IN' | 'SIGNED_OUT' | 'TOKEN_REFRESHED' | 'USER_UPDATED';
export type EmailVerificationType = 'signup' | 'recovery' | 'email' | 'email_change' | 'magiclink';
export type VerifyOtpInput =
  | {email: string; token: string; type: EmailVerificationType; token_hash?: never}
  | {token_hash: string; type: EmailVerificationType; email?: never; token?: never};
interface PendingOAuth { verifier: string; redirectTo: string; createdAt: number }
const copy = <T>(value: T): T => structuredClone(value);
function sessionFrom(raw: unknown): Session | null {
  if (!raw || typeof raw !== 'object') return null;
  const r = raw as Record<string, unknown>;
  const accessToken = r.access_token ?? r.accessToken;
  const refreshToken = r.refresh_token ?? r.refreshToken;
  const expiresAt = r.expires_at ?? r.expiresAt ?? (typeof r.expires_in === 'number' ? Math.floor(Date.now() / 1000) + r.expires_in : undefined);
  const user = r.user as User | undefined;
  if (typeof accessToken !== 'string' || !accessToken || /\s/.test(accessToken) || typeof refreshToken !== 'string' || !refreshToken || typeof expiresAt !== 'number' || !Number.isFinite(expiresAt) || !user || typeof user.id !== 'string') return null;
  return {accessToken, refreshToken, expiresAt, user};
}
function randomVerifier(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  return btoa(String.fromCharCode(...bytes)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function redirectUrl(value: string): URL {
  let u: URL;
  try { u = new URL(value); } catch { throw new StayoError('Invalid OAuth redirect.', 'invalid_redirect'); }
  if ((u.protocol !== 'https:' && !(u.protocol === 'http:' && ['localhost','127.0.0.1','[::1]'].includes(u.hostname))) || u.username || u.password || u.hash || ['code','error','error_description','error_code'].some(k => u.searchParams.has(k))) throw new StayoError('Use an exact HTTPS or loopback callback URL.', 'invalid_redirect');
  return u;
}
export class StayoAuth {
  readonly storageKey: string;
  private readonly storage: StorageAdapter;
  private session: Session | null = null;
  private generation = 0;
  // Changes only when the signed-in account changes (or the client signs out),
  // never on an attempt that fails or a refresh within one account.
  private identity = 0;
  private refreshWork: Promise<Session> | null = null;
  private writes: Promise<void> = Promise.resolve();
  private readonly ready: Promise<void>;
  private readonly listeners = new Set<(event: AuthEvent, session: Session | null) => void>();
  private timer: ReturnType<typeof setTimeout> | undefined;
  private destroyed = false;
  private oauthWork = false;
  private oauthGeneration = 0;
  constructor(private readonly http: HTTP, private readonly options: ClientOptions) {
    this.storageKey = `stayo:${encodeURIComponent(http.origin)}:${encodeURIComponent(options.storageNamespace ?? 'default')}`;
    if (options.persistSession === false) this.storage = new MemoryStorage();
    else if (options.storage) this.storage = options.storage;
    else {
      try { this.storage = typeof window !== 'undefined' ? window.localStorage : new MemoryStorage(); }
      catch { this.storage = new MemoryStorage(); }
    }
    this.ready = this.restore();
  }
  private async restore(): Promise<void> {
    const generation = this.generation;
    let raw: string | null;
    try { raw = await this.storage.getItem(this.storageKey); } catch { throw new StayoError('Session storage is unavailable.', 'storage_error'); }
    if (generation !== this.generation || this.destroyed || !raw) return;
    try { this.session = sessionFrom(JSON.parse(raw)); } catch { this.session = null; }
    if (!this.session) await this.write(this.storageKey, null);
    this.schedule();
  }
  private write(key: string, value: string | null): Promise<void> {
    const work = this.writes.catch(() => {}).then(async () => {
      try { if (value === null) await this.storage.removeItem(key); else await this.storage.setItem(key, value); }
      catch { throw new StayoError('Session storage is unavailable.', 'storage_error'); }
    });
    this.writes = work; return work;
  }
  private emit(event: AuthEvent): void {
    for (const listener of this.listeners) { try { listener(event, copy(this.session)); } catch { /* App callbacks cannot break session transitions. */ } }
  }
  onAuthStateChange(listener: (event: AuthEvent, session: Session | null) => void): () => void { this.listeners.add(listener); return () => this.listeners.delete(listener); }
  private schedule(): void {
    clearTimeout(this.timer);
    if (this.destroyed || !this.session || !(this.options.autoRefresh ?? typeof window !== 'undefined')) return;
    const delay = Math.max(1000, (this.session.expiresAt * 1000 - Date.now()) - 60000);
    this.timer = setTimeout(() => { void this.refreshSession().catch(() => { if (!this.destroyed && this.session) { this.timer = setTimeout(() => this.schedule(), 10000); (this.timer as unknown as {unref?: () => void}).unref?.(); } }); }, Math.min(delay, 2147483647));
    (this.timer as unknown as {unref?: () => void}).unref?.();
  }
  // A refresh continues the current identity; any other change of account,
  // including signing in from signed out, starts a new one.
  private replaceSession(next: Session | null, refresh = false): void {
    if (!refresh && (this.session?.user.id ?? null) !== (next?.user.id ?? null)) this.identity++;
    this.session = next;
  }
  private async accept(raw: unknown, generation: number, event: AuthEvent, oauthGeneration?: number): Promise<Session> {
    const session = sessionFrom(raw);
    if (!session) throw new StayoError('Auth service returned an invalid session.', 'invalid_session');
    if (generation !== this.generation || this.destroyed) throw new StayoError('Auth operation superseded.', 'auth_superseded');
    if (oauthGeneration !== undefined && oauthGeneration !== this.oauthGeneration) throw new StayoError('OAuth operation canceled.', 'invalid_callback');
    const previousSession = this.session; clearTimeout(this.timer);
    this.replaceSession(session, event === 'TOKEN_REFRESHED');
    await this.write(this.storageKey, JSON.stringify(session));
    if (oauthGeneration !== undefined && oauthGeneration !== this.oauthGeneration) {
      if (this.session === session) {
        this.replaceSession(previousSession); await this.write(this.storageKey, previousSession ? JSON.stringify(previousSession) : null); this.schedule();
      }
      throw new StayoError('OAuth operation canceled.', 'invalid_callback');
    }
    if (generation !== this.generation || this.session !== session || this.destroyed) throw new StayoError('Auth operation superseded.', 'auth_superseded');
    this.schedule(); this.emit(event); return copy(session);
  }
  async getSession(): Promise<Session | null> { await this.ready; return copy(this.session); }
  /** @internal Identity lifetime used to reject responses across account transitions. */
  authGeneration(): number { return this.identity; }
  async accessToken(): Promise<string | null> {
    await this.ready;
    if (this.destroyed) throw new StayoError('Client has been disposed.', 'client_disposed');
    if (this.session && this.session.expiresAt <= Date.now()/1000 + 30) return (await this.refreshSession()).accessToken;
    return this.session?.accessToken ?? null;
  }
  async signUp(input: {email: string; password: string; data?: Record<string, unknown>}, opts: RequestOptions = {}): Promise<{user: User | null; session: Session | null}> {
    await this.ready; const generation = ++this.generation; this.refreshWork = null;
    const r = await this.http.json<Record<string, unknown>>('/auth/v1/signup', {...opts, method: 'POST', anonymous: true, body: input});
    const session = sessionFrom(r);
    return {user: (r.user as User | undefined) ?? (typeof r.id === 'string' ? r as unknown as User : null), session: session ? await this.accept(r, generation, 'SIGNED_IN') : null};
  }
  async signInWithPassword(input: {email: string; password: string}, opts: RequestOptions = {}): Promise<Session> {
    await this.ready; const generation = ++this.generation; this.refreshWork = null;
    const raw = await this.http.json('/auth/v1/token?grant_type=password', {...opts, method: 'POST', anonymous: true, body: input});
    return this.accept(raw, generation, 'SIGNED_IN');
  }
  async refreshSession(): Promise<Session> {
    await this.ready;
    if (this.refreshWork) return this.refreshWork;
    if (!this.session || this.destroyed) throw new StayoError('Sign in before refreshing the session.', 'not_authenticated');
    const generation = this.generation;
    const originatingSession = this.session;
    const refreshToken = originatingSession.refreshToken;
    const work = (async () => {
      try {
        const raw = await this.http.json('/auth/v1/token?grant_type=refresh_token', {method: 'POST', anonymous: true, body: {refresh_token: refreshToken}});
        if (this.session !== originatingSession) throw new StayoError('Refresh belongs to a superseded session.', 'auth_superseded');
        return await this.accept(raw, generation, 'TOKEN_REFRESHED');
      } catch (e) {
        if (e instanceof StayoError && [400,401,403].includes(e.status) && generation === this.generation && this.session === originatingSession) {
          this.replaceSession(null); clearTimeout(this.timer); await this.write(this.storageKey, null); if (generation === this.generation && this.session === null) this.emit('SIGNED_OUT');
        }
        throw e;
      }
    })();
    this.refreshWork = work;
    try { return await work; } finally { if (this.refreshWork === work) this.refreshWork = null; }
  }
  async signOut(opts: RequestOptions = {}): Promise<void> {
    ++this.generation; ++this.identity; this.refreshWork = null;
    await this.ready;
    const token = this.session?.accessToken;
    this.replaceSession(null); clearTimeout(this.timer); this.emit('SIGNED_OUT');
    await Promise.all([this.write(this.storageKey, null), this.cancelOAuth()]);
    if (token) await this.http.request('/auth/v1/logout?scope=local', {...opts, method: 'POST', token});
  }
  async getUser(opts: RequestOptions = {}): Promise<User> {
    const token = await this.accessToken();
    if (!token) throw new StayoError('Sign in first.', 'not_authenticated');
    return this.http.json<User>('/auth/v1/user', {...opts, token});
  }
  async updatePassword(password: string, opts: RequestOptions = {}): Promise<User> {
    const token = await this.accessToken(); if (!token) throw new StayoError('Sign in first.', 'not_authenticated');
    const generation = this.generation;
    const originatingSession = this.session;
    const user = await this.http.json<User>('/auth/v1/user', {...opts, token, method: 'PUT', body: {password}});
    if (originatingSession && this.session === originatingSession && generation === this.generation) {
      const updatedSession = {...originatingSession, user}; this.session = updatedSession;
      await this.write(this.storageKey, JSON.stringify(updatedSession));
      if (this.session === updatedSession && generation === this.generation) this.emit('USER_UPDATED');
    }
    return user;
  }
  async recoverPassword(email: string, opts: RequestOptions & {redirectTo?: string} = {}): Promise<void> {
    if (opts.redirectTo && !this.allowedRedirect(opts.redirectTo)) throw new StayoError('Redirect is not allowlisted.', 'invalid_redirect');
    const query = opts.redirectTo ? `?redirect_to=${encodeURIComponent(opts.redirectTo)}` : '';
    await this.http.request(`/auth/v1/recover${query}`, {...opts, method: 'POST', anonymous: true, body: {email}});
  }
  async verifyOtp(input: VerifyOtpInput, opts: RequestOptions = {}): Promise<{user: User | null; session: Session | null}> {
    const invalid = () => new StayoError('Use an email and code, or a token hash, with an email verification type.', 'invalid_verification');
    if (!input || typeof input !== 'object' || Array.isArray(input) || !['signup','recovery','email','email_change','magiclink'].includes(input.type)) throw invalid();
    let body: Record<string, string>;
    if ('token_hash' in input) {
      if ('email' in input || 'token' in input || typeof input.token_hash !== 'string' || !input.token_hash || /\s/.test(input.token_hash)) throw invalid();
      body = {token_hash: input.token_hash, type: input.type};
    } else {
      if (typeof input.email !== 'string' || !/^[^@\s]+@[^@\s]+$/.test(input.email) || typeof input.token !== 'string' || !input.token || /\s/.test(input.token)) throw invalid();
      body = {email: input.email, token: input.token, type: input.type};
    }
    await this.ready; const generation = ++this.generation; this.refreshWork = null;
    const r = await this.http.json<Record<string, unknown>>('/auth/v1/verify', {...opts, method: 'POST', anonymous: true, body});
    return {user: (r.user as User | undefined) ?? (typeof r.id === 'string' ? r as unknown as User : null), session: sessionFrom(r) ? await this.accept(r, generation, 'SIGNED_IN') : null};
  }
  private allowedRedirect(value: string): boolean {
    const normalized = redirectUrl(value).href;
    return (this.options.oauthRedirectUrls ?? []).some(r => redirectUrl(r).href === normalized);
  }
  async beginOAuth(input: {provider: 'google'|'apple'; redirectTo: string}): Promise<{url: string}> {
    await this.ready;
    if (!['google','apple'].includes(input.provider) || !this.allowedRedirect(input.redirectTo)) throw new StayoError('Provider or redirect is not allowed.', 'invalid_redirect');
    const oauthGeneration = ++this.oauthGeneration;
    const verifier = randomVerifier();
    const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier));
    const challenge = btoa(String.fromCharCode(...new Uint8Array(digest))).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
    if (oauthGeneration !== this.oauthGeneration || this.destroyed) throw new StayoError('OAuth operation canceled.', 'invalid_callback');
    const redirectTo = redirectUrl(input.redirectTo).href;
    await this.write(`${this.storageKey}:pkce`, JSON.stringify({verifier, redirectTo, createdAt:Date.now()}));
    const u = new URL('/auth/v1/authorize', this.http.origin);
    u.search = new URLSearchParams({provider:input.provider,redirect_to:redirectTo,code_challenge:challenge,code_challenge_method:'s256',apikey:this.http.key}).toString();
    // GoTrue owns and validates provider OAuth state; redirect_to stays exact.
    return {url:u.href};
  }
  async cancelOAuth(): Promise<void> { ++this.oauthGeneration; await this.write(`${this.storageKey}:pkce`, null); }
  async completeOAuth(callbackUrl: string, opts: RequestOptions = {}): Promise<Session> {
    await this.ready;
    if (this.oauthWork) throw new StayoError('OAuth callback is already being processed.', 'invalid_callback');
    this.oauthWork = true;
    const oauthGeneration = this.oauthGeneration;
    try {
      await this.writes.catch(() => {});
      let raw: string | null;
      try { raw = await this.storage.getItem(`${this.storageKey}:pkce`); } catch { throw new StayoError('Session storage is unavailable.', 'storage_error'); }
      if (oauthGeneration !== this.oauthGeneration) throw new StayoError('OAuth operation canceled.', 'invalid_callback');
      // Consume before validation/network dispatch; do not cancel our own attempt.
      await this.write(`${this.storageKey}:pkce`, null);
      let pending: PendingOAuth;
      try { pending = JSON.parse(raw ?? 'null') as PendingOAuth; } catch { throw new StayoError('OAuth attempt is missing or expired.', 'invalid_callback'); }
      let callback: URL;
      try { callback = new URL(callbackUrl); } catch { throw new StayoError('Invalid OAuth callback.', 'invalid_callback'); }
      const code = callback.searchParams.get('code');
      if (callback.searchParams.getAll('code').length !== 1) throw new StayoError('OAuth callback has no unique code.', 'invalid_callback');
      for (const key of ['code','error','error_description','error_code']) callback.searchParams.delete(key);
      const expected = pending && typeof pending.redirectTo === 'string' ? new URL(pending.redirectTo) : null;
      callback.searchParams.sort(); expected?.searchParams.sort();
      if (!pending || typeof pending.verifier !== 'string' || typeof pending.createdAt !== 'number' || Date.now()-pending.createdAt > 600000 || Date.now()<pending.createdAt || !this.allowedRedirect(pending.redirectTo) || callback.href !== expected?.href || !code || new URL(callbackUrl).searchParams.has('error')) throw new StayoError('OAuth callback is canceled, mismatched or expired.', 'invalid_callback');
      if (oauthGeneration !== this.oauthGeneration) throw new StayoError('OAuth operation canceled.', 'invalid_callback');
      const generation = ++this.generation; this.refreshWork = null;
      const result = await this.http.json('/auth/v1/token?grant_type=pkce', {...opts, method:'POST', anonymous:true, body:{auth_code:code,code_verifier:pending.verifier}});
      if (oauthGeneration !== this.oauthGeneration) throw new StayoError('OAuth operation canceled.', 'invalid_callback');
      return await this.accept(result,generation,'SIGNED_IN',oauthGeneration);
    } finally { this.oauthWork = false; }
  }
  dispose(): void { this.destroyed = true; ++this.generation; ++this.identity; ++this.oauthGeneration; clearTimeout(this.timer); this.listeners.clear(); }
}
