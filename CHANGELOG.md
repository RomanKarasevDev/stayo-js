# Changelog

## 0.1.0 (unpublished)

- Browser, Node.js and request-scoped SSR clients without Supabase libraries.
- Auth and PKCE, typed database/RPC, files, functions and INSERT/UPDATE Realtime.
- Email/code confirmation and recovery; bounded nested Functions error codes.
- Session refresh/logout barriers and explicit resynchronization after reconnect.
- Database, RPC and Storage responses that arrive after sign-out or an account
  switch fail with `auth_superseded` instead of reaching the next identity; no
  request is retried. A failed sign-in attempt or a token refresh keeps the
  current identity, so its requests complete normally.
- Portable guides and a shared UUID notes schema for all three SDK examples.

Public registry availability, real OAuth and physical-device acceptance are
separate release gates. Cancelling a client request does not guarantee immediate
server slot release or undo completed external work.
