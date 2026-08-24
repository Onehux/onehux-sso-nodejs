# Changelog

All notable changes to `@onehux/sso` are documented here.

## 0.2.0

- **Added** `OneHuxClient.refreshAccessToken()` (`grant_type=refresh_token`, backend repo
  README.md ADR-081: RFC 6749 §6 / RFC 9700 §4.14.2 rotation with reuse detection).
  `TokenResult` now carries a real `refreshToken` field, returned by both `exchangeCode()` and
  `refreshAccessToken()`. Throws `TokenExpiredError` on any rejected refresh (expired,
  already-rotated/reuse, or the underlying session revoked — indistinguishable by design, per
  RFC 9700 §4.14.2, so the client has no more information to offer a caller than "not valid
  anymore").
- `createOneHuxRouter()`'s `GET /userinfo` now attempts exactly one silent refresh using the
  session's stored refresh token before surfacing `TokenExpiredError`, persisting the
  newly-rotated token pair back into the session (refresh tokens are single-use). A rejected
  refresh clears both stored tokens and forces a full re-login (`401`); a transient network
  failure during the refresh call itself does not, and surfaces as `502` — the same
  transient-failure boundary every other network call in this package already uses, never
  downgraded to a fabricated "session expired."
- The refresh token itself is stored under an internal, non-configurable session key
  (`onehuxSsoRefreshToken`) — deliberately not exposed as a configurable option the way
  `sessionAccessTokenKey` is, since it's a single-use, rotating credential; integrator code
  reading/using it directly would risk a double-rotation race against this router's own retry
  path.
- `TokenExpiredError`'s meaning evolves accordingly: no longer "no refresh token exists," now
  "not signed in, full stop" — thrown only after a refresh was attempted and also failed, or
  none was available.
- Verified against a real, running local backend (not just mocked unit tests): real
  `authorization_code` exchange, real `/userinfo` calls, real rotation, and the router's
  refresh-and-retry path exercised end to end (`src/express.test.ts`), plus `refreshAccessToken()`
  unit-tested directly against a mocked token endpoint for both the rotation-success and
  rejected-token cases (`src/client.test.ts`).
- `example/server.js` and the README updated to match — the "No refresh token today" section
  replaced with a real "Refresh tokens" section.

## 0.1.1

- Publish readiness: bumped the Node engines floor to `>=22` (Node 18 confirmed EOL; Node 20's
  security support also ended), renamed the package to `@onehux/sso` under the npm org scope
  with `publishConfig.access=public`, and finalized the license as Apache 2.0 (replacing an
  MIT placeholder).
- Added a real unit test suite (`src/client.test.ts`, 20 tests, Vitest): PKCE
  generation/matching, every error-type branch, every URL-building method, and `logout_token`
  HMAC verification — plus `.github/workflows/test.yml` running typecheck + build + that suite
  across every currently-supported Node.js LTS line.
- Fixed a real provenance-verification failure: `package.json` was missing the
  `repository`/`homepage` fields npm's provenance check requires.
- README-only follow-up: real published install commands, OIDC (Trusted Publishing) publish
  workflow documented to match how this package actually ships.

## 0.1.0

Initial release. Real, installable npm package wrapping OneHux Accounts' Authorization Code +
PKCE flow — formalizing what the Node.js integration guide otherwise only shows as example
code. Two entrypoints: a framework-agnostic `OneHuxClient`, and an optional Express router
(`onehux-sso/express`) so Express is never a hard dependency of the base client. Includes a
working example Express app, run end-to-end against a real disposable backend test fixture:
hosted-login redirect, sign-in, token exchange, `/userinfo`, and RP-initiated logout all
confirmed working.

Two real, documented constraints at this release: no refresh token issued yet
(`TokenExpiredError` made this explicit — see 0.2.0 above for when this changed), and OIDC
Back-Channel Logout wasn't implemented yet either.
