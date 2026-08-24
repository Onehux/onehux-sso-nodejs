# @onehux/sso

A real, installable Node.js/TypeScript SDK wrapping OneHux Accounts' Authorization Code + PKCE
flow against its real hosted login page — formalizing what
[the Node.js integration guide](https://accounts.onehux.com/dashboard/docs/integrate/backend/nodejs)
otherwise only shows as copy-paste example code.

Two entrypoints:

- `@onehux/sso` — the framework-agnostic `OneHuxClient` (PKCE, token exchange, `/userinfo`,
  logout URL). No dependency on Express or any particular session store.
- `@onehux/sso/express` — `createOneHuxRouter()`, wiring `OneHuxClient` to a real
  `express-session`. Only import this if you're using Express; it's a separate entrypoint
  precisely so the framework-agnostic client above never requires Express to be installed.

## Install

```bash
npm install @onehux/sso
```

[npmjs.com/package/@onehux/sso](https://www.npmjs.com/package/@onehux/sso)

## Two hosts — don't mix them up

`accounts.onehux.com` serves the hosted login/logout pages a browser is redirected to.
`api-accounts.onehux.com` serves the actual OAuth API your backend calls server-to-server. This
package keeps them as two separate options (`loginBaseUrl` / `apiBaseUrl`) precisely because
collapsing them into one host was a real, confirmed bug in the original integration guides (see
the backend repo's `README.md`, ADR-070) — the wrong host doesn't error loudly, it silently
404s.

**If your Organization has a live custom domain** (Dashboard → Settings → Branding, see the
backend repo's `README.md` ADR-027), set `loginBaseUrl` to that domain instead — it's what your
end users' browsers actually land on, so it should match whatever you've branded. Never override
`apiBaseUrl`: it has no per-Organization customization and never needs any — every call there is
server-to-server via your `clientId`/`clientSecret`, never seen by an end user.

## Setup — using the Express router

1. Register a real confidential-client `Application` in your OneHux Accounts Organization
   (Dashboard → Applications), with a `redirect_uri` pointing at wherever you mount this
   package's `/callback` route, **and** your `post_logout_redirect_uri` registered in that same
   list — OneHux Accounts validates both against the one `redirect_uris` list, not two separate
   ones.

2. Wire it up:

   ```ts
   import express from 'express';
   import session from 'express-session';
   import { OneHuxClient } from '@onehux/sso';
   import { createOneHuxRouter } from '@onehux/sso/express';

   const client = new OneHuxClient({
     clientId: process.env.ONEHUX_CLIENT_ID!,
     clientSecret: process.env.ONEHUX_CLIENT_SECRET!,
     redirectUri: 'https://yourapp.example.com/auth/callback',
     postLogoutRedirectUri: 'https://yourapp.example.com/auth/logged-out'
     // loginBaseUrl / apiBaseUrl / scope all have real production defaults — see src/client.ts
   });

   const app = express();
   app.use(session({ secret: process.env.SESSION_SECRET!, resave: false, saveUninitialized: false }));
   app.use('/auth', createOneHuxRouter(client));

   app.listen(3000);
   ```

   > **A note on `cookie.maxAge`:** the example above deliberately doesn't set one, which makes
   > it a real browser-session cookie (dies when the browser closes) — not because that's
   > required, but because it's the safest default given the next paragraph. Whatever `maxAge`
   > you do choose for your own session cookie is **independent** of how long the user actually
   > stays signed in. `createOneHuxRouter()`'s `/auth/userinfo` route now silently refreshes an
   > expired access token using the stored refresh token (see "Refresh tokens" below) — so a
   > signed-in user's real session length is bounded by the refresh token's own lifetime (30
   > days for a confidential client like this one; see the backend repo's README.md ADR-081),
   > not by the access token's 15 minutes, and *also* not by your cookie's `maxAge`. If your
   > cookie's `maxAge` outlives the refresh token itself, the cookie will still exist but
   > `/auth/userinfo` will eventually throw `TokenExpiredError` anyway once the refresh token
   > itself expires or is rejected — that's still real and still possible, just on a longer,
   > rotation-extended clock instead of a flat 15 minutes.

   This gives you four real, working routes: `/auth/login`, `/auth/callback`, `/auth/logout`,
   and `/auth/userinfo` (a ready-to-use JSON endpoint your own frontend can call with
   `credentials: 'include'`, matching the BFF pattern documented for the web-frontend
   integration guide — your frontend never talks to OneHux directly) — plus a fifth,
   `/auth/backchannel-logout`, which only does anything once you configure it (see "Logging
   out" below).

## Using the client directly (any framework, or a custom flow)

```ts
import { OneHuxClient, TokenExpiredError } from '@onehux/sso';

const client = new OneHuxClient({ /* ...same options as above... */ });

const pending = client.startAuthorization();
// stash pending.state / pending.codeVerifier in your own session, then redirect the browser
// to pending.authorizationUrl

const tokens = await client.exchangeCode({
  code: req.query.code,
  state: req.query.state,
  expectedState: session.onehuxSsoState,
  codeVerifier: session.onehuxSsoPkceVerifier
});

let claims;
try {
  claims = await client.getUserinfo({ accessToken: tokens.accessToken });
} catch (err) {
  if (err instanceof TokenExpiredError && session.onehuxSsoRefreshToken) {
    // getUserinfo() never retries itself (it's a pure API call wrapper, no session concept) —
    // a caller using OneHuxClient directly owns this retry, same as createOneHuxRouter()'s own
    // /auth/userinfo route does internally. See "Refresh tokens" below.
    const refreshed = await client.refreshAccessToken({ refreshToken: session.onehuxSsoRefreshToken });
    session.onehuxSsoRefreshToken = refreshed.refreshToken; // rotated — persist the new one
    claims = await client.getUserinfo({ accessToken: refreshed.accessToken });
  } else {
    throw err;
  }
}

const logoutUrl = client.buildLogoutUrl();
```

## Public application launcher

`GET /api/v1/organizations/{orgSlug}/public-applications/` is a real, public, unauthenticated
platform endpoint — no `clientId`/`clientSecret` involved, usable for any Organization by its own
slug, not just your own configured one. It returns only `name`/`logoUrl`/`homeUrl` for
Applications that Organization has opted into public listing — a pure "what can I launch" list,
never a way to start a sign-in flow.

```ts
const apps = await client.getPublicApplications({ orgSlug: 'onehux' });
// [{ name: 'ODS', logoUrl: 'https://...', homeUrl: 'https://...' }]
```

Rendering is entirely up to you — this package ships the data method only, no UI component (this
package spans too many rendering approaches — EJS, React SSR, a separate SPA — to have one
honest "standard" to build against). A plain, unstyled illustration (adapt this to your own
design, don't copy it as-is):

```html
${apps.map(app => `<a href="${app.homeUrl}"><img src="${app.logoUrl}" alt="${app.name}">${app.name}</a>`).join('')}
```

## Logging out — what the user actually sees

There are two different triggers, and — once you wire up back-channel logout (below) — they
produce the same fast, correct result. Understanding both is still worth it, since the second
one only becomes immediate if you actually complete the setup:

**1. The user clicks "Log out" inside your app (SP-initiated).** Your app's own `/auth/logout`
route clears its local session *and* redirects through `/end-session` in the same action,
which ends the real, shared platform session immediately. From the user's point of view: they
click Log out, land on your app's own logged-out page, and if they then open the dashboard or
any other app, they're asked to log in again — everywhere, right away. This works cleanly
because your own app is the one driving both halves of the logout at once, with no dependency
on back-channel logout at all.

**2. The user logs out somewhere else — a different app, or directly at
`accounts.onehux.com`/the dashboard (IdP-initiated).** The shared platform session is revoked
immediately and correctly on the backend — same underlying revocation call as case 1. Whether
*your app* finds out immediately depends entirely on whether you've completed the back-channel
logout setup below:

- **With it wired up:** OneHux POSTs a signed `logout_token` to your `/auth/backchannel-logout`
  route the instant the session is revoked. This package verifies it and destroys the matching
  local Express session server-side. From the user's point of view: functionally identical to
  case 1 — if they reload or navigate, they're asked to log in again right away, even though
  they never touched this app's own logout button.
- **Without it:** your app has no way to find out proactively. It'll keep showing the user as
  signed in — its own local session cookie hasn't changed — right up until the moment it makes
  its next real call to `/userinfo`, which returns a real `401`/`TokenExpiredError`. In the
  worst realistic case, that's **up to 15 minutes** of stale "signed in" UI, bounded by the
  access token's own lifetime. This is not a security hole — no protected data actually leaks,
  since the real API call starts failing the moment it's tried — but the *displayed* state can
  look stale for that window.

**To wire up back-channel logout:**

1. Pass `backchannelLogoutSigningSecret` to `createOneHuxRouter()` — this enables the
   `POST /auth/backchannel-logout` route (mounted automatically alongside the other four).
2. Register that exact URL with OneHux:
   ```
   PATCH /api/v1/applications/{id}/backchannel-logout/
   { "backchannel_logout_uri": "https://yourapp.example.com/auth/backchannel-logout" }
   ```
   The response includes `backchannel_logout_secret` **exactly once** — this is a dedicated
   signing secret, deliberately **not** your `clientSecret` (the backend stores that only as a
   one-way hash and can never read it back to sign anything with it). Use that value as
   `backchannelLogoutSigningSecret`.
3. If you run more than one Node.js process (a real production deployment almost certainly
   does), also pass a `sidIndex` implementation backed by shared storage (Redis, etc.) — the
   default `InMemorySidIndex` only works within a single process, since the process that
   receives the `logout_token` POST may not be the same one that handled the original login.

```ts
const app = express();
app.use(session({ /* ... */ }));
app.use(
  '/auth',
  createOneHuxRouter(client, {
    backchannelLogoutSigningSecret: process.env.ONEHUX_BACKCHANNEL_LOGOUT_SECRET!
    // sidIndex: new RedisSidIndex(redisClient)  — supply this in a multi-process deployment
  })
);
```

Spec: [openid-connect-backchannel-1_0](https://openid.net/specs/openid-connect-backchannel-1_0.html).

## Refresh tokens

OneHux Accounts access tokens are a 15-minute, single-issue lifetime — that hasn't changed. What
has: every real login now also issues a **refresh token** (backend repo README.md ADR-081, RFC
6749 §6 / RFC 9700 §4.14.2 rotation with reuse detection), which this package uses to renew an
expired access token without a full re-login.

`createOneHuxRouter()`'s `GET /auth/userinfo` route does this automatically: an expired access
token triggers exactly one silent `refreshAccessToken()` call using the session's stored refresh
token, and the retried `/userinfo` call's real claims are what the caller actually sees — never
surfaced as an error unless the refresh itself also fails. The new access/refresh token pair is
persisted back into the session, replacing the old one (a refresh token is **single-use and
rotates on every real use** — the old value stops working the moment a new one is issued).

`TokenExpiredError` is still the error you catch, but its meaning is now "not signed in, full
stop" rather than "the 15-minute access token died" — it's thrown only once a refresh has
already been attempted and failed too (or no refresh token was ever stored, e.g. a session from
before this package version). In every one of those cases, catch it and send the user back
through `client.startAuthorization()` for a fresh login. The backend deliberately does not tell
this package *why* a refresh failed — ordinary expiry, an already-rotated token being replayed
(a real reuse/compromise signal), or the underlying session being revoked all produce the same
generic rejection (RFC 9700 §4.14.2's own reasoning: the server can't tell which party presented
the stale token) — so this package has nothing more specific to offer a caller than "not valid
anymore."

If you call `client.getUserinfo()` yourself outside of `createOneHuxRouter()` (see
`example/server.js`), it never retries on your behalf — it's a pure API call wrapper with no
session concept. Catch `TokenExpiredError`, call `client.refreshAccessToken()` yourself if you
have a stored refresh token, persist the newly-rotated one, and retry once — see "Using the
client directly" above for the real pattern.

**Public clients** (a future mobile/desktop SDK, no `client_secret`) get tighter refresh-token
settings than this package's confidential-client model (7-day idle timeout / 14-day absolute
lifetime vs. 30/30 here) — not relevant to this package today, but worth knowing the number
"30 days" above isn't a platform-wide constant.

## Example project

See `example/` for a complete, runnable Express app using this package end-to-end — registered
against a real disposable test `Application` and actually run through the full browser flow
against production, not just unit-tested in isolation.

## Build

```bash
npm install
npm run build      # tsup — dual ESM/CJS + .d.ts, two entrypoints (index, express)
npm run typecheck  # tsc --noEmit
```

## License

Apache License 2.0 — see `LICENSE`.
