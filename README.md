# onehux-sso

A real, installable Node.js/TypeScript SDK wrapping OneHux Accounts' Authorization Code + PKCE
flow against its real hosted login page — formalizing what
[the Node.js integration guide](https://accounts.onehux.com/dashboard/docs/integrate/backend/nodejs)
otherwise only shows as copy-paste example code.

Two entrypoints:

- `onehux-sso` — the framework-agnostic `OneHuxClient` (PKCE, token exchange, `/userinfo`,
  logout URL). No dependency on Express or any particular session store.
- `onehux-sso/express` — `createOneHuxRouter()`, wiring `OneHuxClient` to a real
  `express-session`. Only import this if you're using Express; it's a separate entrypoint
  precisely so the framework-agnostic client above never requires Express to be installed.

## Install

```bash
npm install /path/to/onehux_sso_client/nodejs-package
```

(Not yet published to npm — install from a local path/tarball until that's decided.)

## Two hosts — don't mix them up

`accounts.onehux.com` serves the hosted login/logout pages a browser is redirected to.
`api-accounts.onehux.com` serves the actual OAuth API your backend calls server-to-server. This
package keeps them as two separate options (`loginBaseUrl` / `apiBaseUrl`) precisely because
collapsing them into one host was a real, confirmed bug in the original integration guides (see
the backend repo's `README.md`, ADR-070) — the wrong host doesn't error loudly, it silently
404s.

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
   import { OneHuxClient } from 'onehux-sso';
   import { createOneHuxRouter } from 'onehux-sso/express';

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

   This gives you four real, working routes: `/auth/login`, `/auth/callback`, `/auth/logout`,
   and `/auth/userinfo` (a ready-to-use JSON endpoint your own frontend can call with
   `credentials: 'include'`, matching the BFF pattern documented for the web-frontend
   integration guide — your frontend never talks to OneHux directly).

## Using the client directly (any framework, or a custom flow)

```ts
import { OneHuxClient } from 'onehux-sso';

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

const claims = await client.getUserinfo({ accessToken: tokens.accessToken });

const logoutUrl = client.buildLogoutUrl();
```

## Logging out — what the user actually sees

There are two different triggers, and they produce genuinely different observable behavior —
not an abstract "back-channel logout isn't supported" footnote, but a real difference in what
a real user will see:

**1. The user clicks "Log out" inside your app (SP-initiated).** Your app's own `/auth/logout`
route clears its local session *and* redirects through `/end-session` in the same action,
which ends the real, shared platform session immediately. From the user's point of view: they
click Log out, land on your app's own logged-out page, and if they then open the dashboard or
any other app, they're asked to log in again — everywhere, right away. This works cleanly
because your own app is the one driving both halves of the logout at once.

**2. The user logs out somewhere else — a different app, or directly at
`accounts.onehux.com`/the dashboard (IdP-initiated).** The shared platform session is revoked
immediately and correctly on the backend — this part is not delayed or broken. But *your app
was never told*. From the user's point of view: if they still have a tab open on your app and
click around, your app will keep showing them as signed in — its own local session cookie
hasn't changed — right up until the moment it makes its next real call to `/userinfo` (e.g.
loading a page that calls `getUserinfo()` or hits `/auth/userinfo`). At that point they get a
real `401`/`TokenExpiredError`, and (if your app handles that correctly) get routed back
through login. In the worst realistic case, that's **up to 15 minutes** of your app's UI
showing a user as signed in when the backend already considers them logged out everywhere
else. This is not a security hole — no protected data actually leaks, because the real API
call will start failing the moment it's tried — but the *displayed* state can look stale to
that specific user for up to that window.

This is the standard limitation of OAuth/OIDC SSO without **OIDC Back-Channel Logout** (a
formal spec extension where the IdP proactively pushes a logout notification to every SP) —
OneHux Accounts does not implement it today. Plan your UI around this rather than assuming a
locally-held "signed in" state is a live signal of the IdP's true logout state — e.g., poll
`/auth/userinfo` periodically on sensitive pages, or simply accept the bounded staleness window
as this platform currently guarantees no worse than the access token's own 15-minute lifetime.

## No refresh token today — this is real, not a bug

OneHux Accounts access tokens are a 15-minute, single-issue lifetime. This platform does not
currently issue a refresh token. `client.getUserinfo()` throws `TokenExpiredError` when the
token has expired or been revoked — catch it and send the user back through
`client.startAuthorization()` for a fresh login. There is no silent-refresh path to fall back
to; this package makes that explicit rather than hiding it behind a generic error.

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

MIT (see `LICENSE`) — a default choice, not yet a final decision; change before any public
release if OneHux wants different terms.
