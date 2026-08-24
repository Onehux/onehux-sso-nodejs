// src/client.ts
// OneHuxClient — PKCE generation, the hosted-login redirect, the authorization_code token
// exchange, /userinfo, and the RP-initiated /end-session redirect. Framework-agnostic:
// takes/returns plain strings and objects, no dependency on Express or any session store —
// src/express.ts wires this to a real Express session.
//
// Two distinct hosts, by design (README.md ADR-070 in the backend repo, found by a real
// end-to-end manual walkthrough against production): the hosted login/logout pages live on
// loginBaseUrl, the actual OAuth API lives on the separate apiBaseUrl. Mixing them up
// previously produced a silent 404 HTML body instead of a JSON error — this client never lets
// that ambiguity exist, since the two are separate constructor options, not one shared value.

import { randomBytes, createHash, createHmac, timingSafeEqual } from 'node:crypto';
import {
	InvalidLogoutTokenError,
	InvalidStateError,
	OrganizationNotFoundError,
	StepUpRequiredError,
	TokenExchangeError,
	TokenExpiredError
} from './errors.js';

export const LOGOUT_EVENT_CLAIM_KEY = 'http://schemas.openid.net/event/backchannel-logout';

function base64url(buf: Buffer): string {
	return buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function base64urlDecode(input: string): Buffer {
	return Buffer.from(input.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
}

export interface LogoutTokenPayload {
	iss: string;
	aud: string;
	iat: number;
	exp: number;
	jti: string;
	events: Record<string, unknown>;
	sub?: string;
	sid?: string;
	[key: string]: unknown;
}

export interface OneHuxClientOptions {
	clientId: string;
	clientSecret: string;
	redirectUri: string;
	postLogoutRedirectUri: string;
	loginBaseUrl?: string;
	apiBaseUrl?: string;
	scope?: string;
}

export interface PendingAuthorization {
	codeVerifier: string;
	state: string;
	authorizationUrl: string;
}

/** One entry from GET {apiBaseUrl}/api/v1/organizations/{orgSlug}/public-applications/ —
 * deliberately only name/logoUrl/homeUrl, matching exactly what that endpoint returns. No
 * clientId, no slug, no OAuth-relevant identifier: a pure "what can I launch" list, not a way
 * to start a sign-in flow. */
export interface PublicApplication {
	name: string;
	logoUrl: string;
	homeUrl: string;
}

export interface TokenResult {
	accessToken: string;
	idToken: string;
	refreshToken: string;
	tokenType: string;
	expiresIn: number;
	scope: string;
}

export class OneHuxClient {
	readonly clientId: string;
	readonly clientSecret: string;
	readonly redirectUri: string;
	readonly postLogoutRedirectUri: string;
	readonly loginBaseUrl: string;
	readonly apiBaseUrl: string;
	readonly scope: string;

	constructor(options: OneHuxClientOptions) {
		this.clientId = options.clientId;
		this.clientSecret = options.clientSecret;
		this.redirectUri = options.redirectUri;
		this.postLogoutRedirectUri = options.postLogoutRedirectUri;
		this.loginBaseUrl = (options.loginBaseUrl ?? 'https://accounts.onehux.com').replace(/\/$/, '');
		this.apiBaseUrl = (options.apiBaseUrl ?? 'https://api-accounts.onehux.com').replace(/\/$/, '');
		this.scope = options.scope ?? 'openid profile email';
	}

	/** Generate a fresh PKCE pair + state and build the hosted-login redirect URL. The caller
	 * is responsible for persisting codeVerifier/state server-side (a real session) until the
	 * callback — never in a cookie the browser itself can read. */
	startAuthorization(): PendingAuthorization {
		const codeVerifier = base64url(randomBytes(48));
		const codeChallenge = base64url(createHash('sha256').update(codeVerifier).digest());
		const state = base64url(randomBytes(16));

		const params = new URLSearchParams({
			client_id: this.clientId,
			redirect_uri: this.redirectUri,
			code_challenge: codeChallenge,
			code_challenge_method: 'S256',
			scope: this.scope,
			state
		});
		return {
			codeVerifier,
			state,
			authorizationUrl: `${this.loginBaseUrl}/login?${params.toString()}`
		};
	}

	/** Verify state, then exchange `code` for real tokens via
	 * POST {apiBaseUrl}/api/v1/oauth/token/. Throws InvalidStateError on a state
	 * mismatch/missing code (never attempts the exchange in that case), and TokenExchangeError
	 * carrying the real OAuth error/error_description on a non-2xx response. */
	async exchangeCode(params: {
		code: string;
		state: string;
		expectedState: string | undefined;
		codeVerifier: string | undefined;
	}): Promise<TokenResult> {
		const { code, state, expectedState, codeVerifier } = params;
		if (!code || !state || state !== expectedState) {
			throw new InvalidStateError(
				'Callback state did not match the pending authorization, or code/state was ' +
					'missing — this callback is either stale, replayed, or forged.'
			);
		}

		const response = await fetch(`${this.apiBaseUrl}/api/v1/oauth/token/`, {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({
				grant_type: 'authorization_code',
				code,
				redirect_uri: this.redirectUri,
				client_id: this.clientId,
				client_secret: this.clientSecret,
				code_verifier: codeVerifier
			})
		});
		const body = (await response.json()) as Record<string, unknown>;
		if (!response.ok) {
			if (body.error === 'step_up_required') {
				// Deliberately distinct from TokenExchangeError: this is a recoverable, expected
				// mid-login prompt (device/location trust gate), not a failed exchange — the
				// caller (the /callback route) redirects the browser to complete step-up rather
				// than showing an error.
				throw new StepUpRequiredError({ errorDescription: (body.error_description as string) ?? '' });
			}
			throw new TokenExchangeError({
				error: (body.error as string) ?? 'unknown_error',
				errorDescription: (body.error_description as string) ?? '',
				statusCode: response.status
			});
		}
		return {
			accessToken: body.access_token as string,
			idToken: body.id_token as string,
			refreshToken: body.refresh_token as string,
			tokenType: body.token_type as string,
			expiresIn: body.expires_in as number,
			scope: body.scope as string
		};
	}

	/** Rotates `refreshToken` for a fresh access/id/refresh token triple via
	 * POST {apiBaseUrl}/api/v1/oauth/token/ (grant_type=refresh_token — backend repo README.md
	 * ADR-081). The presented refresh token is invalidated by this call whether it succeeds or
	 * fails to be usable again — the backend's own rotation-with-reuse-detection means a
	 * refresh token is single-use; the caller MUST persist the newly-returned refreshToken and
	 * discard the one just presented, never retry this same call with the old value.
	 *
	 * Throws TokenExpiredError on any non-2xx response — a rejected refresh token means the
	 * family expired, was rotated away already (reuse), or the underlying Session was revoked
	 * (logout, Back-Channel Logout, admin action). In every one of those cases the correct
	 * remedy is the same: send the user through OneHuxClient.startAuthorization() again. This
	 * client deliberately does not distinguish *why* the refresh failed — the backend itself
	 * returns the same generic invalid_grant for an ordinary expiry and a detected compromise
	 * (RFC 9700 §4.14.2's own reasoning: it can't tell which party presented the stale token),
	 * so this client has no more information to offer a caller than "not valid anymore." */
	async refreshAccessToken(params: { refreshToken: string }): Promise<TokenResult> {
		const response = await fetch(`${this.apiBaseUrl}/api/v1/oauth/token/`, {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({
				grant_type: 'refresh_token',
				refresh_token: params.refreshToken,
				client_id: this.clientId,
				client_secret: this.clientSecret
			})
		});
		if (!response.ok) {
			throw new TokenExpiredError(
				'The refresh token was rejected — it has expired, was already rotated away, or the ' +
					'underlying session was revoked. Send the user back through ' +
					'OneHuxClient.startAuthorization().'
			);
		}
		const body = (await response.json()) as Record<string, unknown>;
		return {
			accessToken: body.access_token as string,
			idToken: body.id_token as string,
			refreshToken: body.refresh_token as string,
			tokenType: body.token_type as string,
			expiresIn: body.expires_in as number,
			scope: body.scope as string
		};
	}

	/** Build the redirect used when exchangeCode() throws StepUpRequiredError (README.md
	 * ADR-076, backend repo). Reuses this SAME pending authorization's clientId/redirectUri/
	 * scope/state, and re-derives codeChallenge from the already-stored codeVerifier (PKCE
	 * codeChallenge is a pure function of codeVerifier, so nothing extra needs to be persisted).
	 * Deep-links straight to the real hosted email-OTP step-up page — the exact same URL the
	 * platform's own first-party dashboard redirects to for this identical error (backend repo:
	 * frontend/src/lib/server/step-up.ts) — rather than the generic /login page, since the
	 * platform requires a step-up-caliber method specifically here. The caller MUST NOT discard
	 * the pending codeVerifier/state before calling this: the browser will land back on this
	 * same app's callback shortly with a brand-new code for this same state, and the callback
	 * route needs the still-stored codeVerifier to exchange it. */
	buildStepUpRedirectUrl(params: { codeVerifier: string; state: string }): string {
		const codeChallenge = base64url(createHash('sha256').update(params.codeVerifier).digest());
		const query = new URLSearchParams({
			client_id: this.clientId,
			redirect_uri: this.redirectUri,
			code_challenge: codeChallenge,
			code_challenge_method: 'S256',
			scope: this.scope,
			state: params.state,
			reason: 'step_up'
		});
		return `${this.loginBaseUrl}/login/email-otp?${query.toString()}`;
	}

	/** GET {apiBaseUrl}/api/v1/oauth/userinfo/ — real claims (sub, name, email, picture,
	 * roles, permissions, ...), recomputed live by the backend on every call, never cached
	 * here. Throws TokenExpiredError on any non-2xx response: OneHux Accounts access tokens
	 * are a 15-minute, single-issue lifetime. This method itself never retries — it's a pure
	 * API call wrapper with no session concept (see this file's own header comment). A caller
	 * holding a refresh token should catch TokenExpiredError, call refreshAccessToken(), and
	 * retry this call once with the new access token — createOneHuxRouter()'s /userinfo route
	 * does exactly that automatically; a caller using OneHuxClient directly must do it itself. */
	async getUserinfo(params: { accessToken: string }): Promise<Record<string, unknown>> {
		const response = await fetch(`${this.apiBaseUrl}/api/v1/oauth/userinfo/`, {
			headers: { Authorization: `Bearer ${params.accessToken}` }
		});
		if (!response.ok) {
			throw new TokenExpiredError(
				'The access token was rejected by /userinfo — it has either expired (15-minute ' +
					'lifetime, no refresh token issued by this platform today) or was revoked. Send ' +
					'the user back through OneHuxClient.startAuthorization().'
			);
		}
		return (await response.json()) as Record<string, unknown>;
	}

	/** GET {apiBaseUrl}/api/v1/organizations/{orgSlug}/public-applications/ — the platform's
	 * public, unauthenticated application-launcher endpoint (README.md ADR-078). No
	 * clientId/clientSecret involved: this is a public, unauthenticated GET, usable for any
	 * Organization by its own slug, not just this client's own configured one. Throws
	 * OrganizationNotFoundError if orgSlug doesn't match a usable Organization. */
	async getPublicApplications(params: { orgSlug: string }): Promise<PublicApplication[]> {
		const response = await fetch(
			`${this.apiBaseUrl}/api/v1/organizations/${encodeURIComponent(params.orgSlug)}/public-applications/`
		);
		if (!response.ok) {
			const body = (await response.json().catch(() => ({}))) as Record<string, unknown>;
			throw new OrganizationNotFoundError({
				errorDescription: (body.error_description as string) ?? 'Organization not found.'
			});
		}
		const items = (await response.json()) as Array<Record<string, string>>;
		return items.map((item) => ({ name: item.name, logoUrl: item.logo_url, homeUrl: item.home_url }));
	}

	/** Build the RP-initiated logout redirect (README.md ADR-070, backend repo):
	 * postLogoutRedirectUri must already be registered in this Application's own redirect_uris
	 * list — the same list the login callback uses, not a separate one — or the platform
	 * rejects this with a real 400. */
	buildLogoutUrl(params?: { state?: string }): string {
		const query: Record<string, string> = {
			client_id: this.clientId,
			post_logout_redirect_uri: this.postLogoutRedirectUri
		};
		if (params?.state) query.state = params.state;
		return `${this.loginBaseUrl}/end-session?${new URLSearchParams(query).toString()}`;
	}

	/** Pull the `sid` claim out of an id_token WITHOUT verifying its signature — this package
	 * cannot verify an id_token's signature at all (OneHux Accounts signs it with a server-only
	 * key never shared with any client — the backend repo's oauth.services.build_jwt() docstring
	 * flags this as a deliberate Phase-1 gap), and doesn't need to for this purpose: the token
	 * was retrieved directly from a clientSecret-authenticated POST to /api/v1/oauth/token/ over
	 * TLS, not an untrusted redirect parameter, so trusting its contents here (indexing this
	 * local session for a later logout_token match) is standard OIDC RP practice. Returns
	 * undefined if the token doesn't decode or has no sid claim. */
	extractSidFromIdToken(idToken: string): string | undefined {
		const parts = idToken.split('.');
		if (parts.length !== 3) return undefined;
		try {
			const payload = JSON.parse(base64urlDecode(parts[1]).toString('utf8')) as Record<string, unknown>;
			return typeof payload.sid === 'string' ? payload.sid : undefined;
		} catch {
			return undefined;
		}
	}

	/** Real OIDC Back-Channel Logout validation (spec §2.6), HS256-verified by hand via
	 * node:crypto — this package has zero runtime dependencies and a full JWT library isn't
	 * worth pulling in for one HMAC check. `signingSecret` is the dedicated secret shown once
	 * when you registered your backchannel_logout_uri via
	 * PATCH /api/v1/applications/{id}/backchannel-logout/ — deliberately NOT this client's own
	 * clientSecret (the backend cannot read that back to sign anything with it; see the backend
	 * repo's README.md ADR-074). Throws InvalidLogoutTokenError on any validation failure. */
	verifyLogoutToken(params: { logoutToken: string; signingSecret: string }): LogoutTokenPayload {
		const { logoutToken, signingSecret } = params;
		const parts = logoutToken.split('.');
		if (parts.length !== 3) {
			throw new InvalidLogoutTokenError('logout_token is not a well-formed JWT.');
		}
		const [headerB64, payloadB64, signatureB64] = parts;

		let header: Record<string, unknown>;
		let payload: LogoutTokenPayload;
		try {
			header = JSON.parse(base64urlDecode(headerB64).toString('utf8'));
			payload = JSON.parse(base64urlDecode(payloadB64).toString('utf8')) as LogoutTokenPayload;
		} catch {
			throw new InvalidLogoutTokenError('logout_token header/payload is not valid JSON.');
		}
		if (header.alg !== 'HS256') {
			throw new InvalidLogoutTokenError(`Unsupported logout_token alg: ${String(header.alg)}`);
		}

		const expectedSignature = createHmac('sha256', signingSecret)
			.update(`${headerB64}.${payloadB64}`)
			.digest();
		let actualSignature: Buffer;
		try {
			actualSignature = base64urlDecode(signatureB64);
		} catch {
			throw new InvalidLogoutTokenError('logout_token signature is not valid base64url.');
		}
		if (
			actualSignature.length !== expectedSignature.length ||
			!timingSafeEqual(actualSignature, expectedSignature)
		) {
			throw new InvalidLogoutTokenError('logout_token signature verification failed.');
		}

		const now = Math.floor(Date.now() / 1000);
		if (typeof payload.exp !== 'number' || payload.exp < now) {
			throw new InvalidLogoutTokenError('logout_token has expired.');
		}
		if (payload.aud !== this.clientId) {
			throw new InvalidLogoutTokenError('logout_token aud does not match this client_id.');
		}
		if ('nonce' in payload) {
			throw new InvalidLogoutTokenError('logout_token MUST NOT contain a nonce claim.');
		}
		if (
			!payload.events ||
			typeof payload.events !== 'object' ||
			!(LOGOUT_EVENT_CLAIM_KEY in payload.events)
		) {
			throw new InvalidLogoutTokenError(
				`logout_token is missing the required events claim (${LOGOUT_EVENT_CLAIM_KEY}).`
			);
		}
		if (!payload.sub && !payload.sid) {
			throw new InvalidLogoutTokenError(
				'logout_token must contain a sub claim, a sid claim, or both.'
			);
		}
		return payload;
	}
}
