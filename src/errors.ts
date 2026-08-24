// src/errors.ts
// Errors raised by the OneHux SSO client. Real backend error shapes (error/error_description)
// are preserved, not swallowed into a generic message.

export class OneHuxSSOError extends Error {}

/** The callback's state parameter didn't match what was stashed at redirect time, or
 * code/state was missing outright — a real CSRF-protection failure, or a stale/replayed
 * callback URL. */
export class InvalidStateError extends OneHuxSSOError {}

/** POST /api/v1/oauth/token/ returned a non-2xx response. Carries the real OAuth
 * error/error_description from oauth.views._error_response() rather than a generic message,
 * so a caller can distinguish e.g. invalid_grant (expired code) from invalid_client
 * (misconfigured client_id/secret). */
export class TokenExchangeError extends OneHuxSSOError {
	readonly error: string;
	readonly errorDescription: string;
	readonly statusCode: number;

	constructor(params: { error: string; errorDescription: string; statusCode: number }) {
		super(`${params.error}: ${params.errorDescription}`);
		this.error = params.error;
		this.errorDescription = params.errorDescription;
		this.statusCode = params.statusCode;
	}
}

/** POST /api/v1/oauth/token/ returned {"error": "step_up_required", ...} (README.md ADR-076,
 * backend repo) — credentials/code were valid, but the platform's device/location trust gate
 * rejected this specific login (password or Google) as coming from an unrecognized
 * device/location. NOT a fatal error: OneHuxClient.exchangeCode() throws this distinctly from
 * TokenExchangeError so the callback route can redirect the browser to complete step-up
 * (magic link/email code/passkey) rather than showing a hard failure — the same automatic-
 * redirect behavior the platform's own first-party dashboard uses for this identical error. */
export class StepUpRequiredError extends OneHuxSSOError {
	readonly errorDescription: string;

	constructor(params: { errorDescription: string }) {
		super(params.errorDescription);
		this.errorDescription = params.errorDescription;
	}
}

/** GET /api/v1/oauth/userinfo/ rejected the access token, OR
 * OneHuxClient.refreshAccessToken() had its refresh token rejected.
 *
 * OneHux Accounts access tokens are a 15-minute lifetime; refresh tokens (backend repo
 * README.md ADR-081) let a caller renew one without a full re-login, but are themselves
 * single-use and eventually expire too. This error means whichever credential was presented —
 * access token or refresh token — is no longer valid, for any reason: ordinary expiry,
 * already-rotated-away reuse, or the underlying session being revoked (logout, Back-Channel
 * Logout, admin action). The backend deliberately does not distinguish these to the caller
 * (RFC 9700 §4.14.2), so neither does this error. Callers must route the user back through
 * OneHuxClient.startAuthorization() for a fresh login — createOneHuxRouter()'s /userinfo route
 * already attempts one silent refresh-and-retry first when a refresh token is stored; this
 * error means that also failed (or no refresh token was available to try). */
export class TokenExpiredError extends OneHuxSSOError {}

/** GET /api/v1/organizations/{orgSlug}/public-applications/ returned a non-2xx response — no
 * Organization matches that slug, or it isn't usable (deactivated/deleted). Carries the real
 * error/error_description from the backend rather than a generic message. */
export class OrganizationNotFoundError extends OneHuxSSOError {
	readonly errorDescription: string;

	constructor(params: { errorDescription: string }) {
		super(params.errorDescription);
		this.errorDescription = params.errorDescription;
	}
}

/** An incoming POST to the /backchannel-logout route failed real OIDC Back-Channel Logout
 * validation (spec §2.6) — bad/missing signature, wrong aud, missing/malformed events claim, a
 * present nonce claim (forbidden), an expired token, or a missing sub/sid. The route turns this
 * into the spec-required HTTP 400, never a 500 — a forged or malformed request on a public
 * endpoint is expected adversarial input, not a server bug. */
export class InvalidLogoutTokenError extends OneHuxSSOError {}
