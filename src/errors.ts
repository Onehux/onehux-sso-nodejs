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

/** GET /api/v1/oauth/userinfo/ rejected the access token.
 *
 * OneHux Accounts does not currently issue a refresh token (access tokens are a 15-minute,
 * single-issue lifetime) — this is a real, permanent platform constraint, not a bug in this
 * client. Callers must catch this and route the user back through
 * OneHuxClient.startAuthorization() for a fresh login; there is no silent-refresh path to fall
 * back to. */
export class TokenExpiredError extends OneHuxSSOError {}

/** An incoming POST to the /backchannel-logout route failed real OIDC Back-Channel Logout
 * validation (spec §2.6) — bad/missing signature, wrong aud, missing/malformed events claim, a
 * present nonce claim (forbidden), an expired token, or a missing sub/sid. The route turns this
 * into the spec-required HTTP 400, never a 500 — a forged or malformed request on a public
 * endpoint is expected adversarial input, not a server bug. */
export class InvalidLogoutTokenError extends OneHuxSSOError {}
