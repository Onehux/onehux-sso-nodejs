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

import { randomBytes, createHash } from 'node:crypto';
import { InvalidStateError, TokenExchangeError, TokenExpiredError } from './errors.js';

function base64url(buf: Buffer): string {
	return buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
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

export interface TokenResult {
	accessToken: string;
	idToken: string;
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
			throw new TokenExchangeError({
				error: (body.error as string) ?? 'unknown_error',
				errorDescription: (body.error_description as string) ?? '',
				statusCode: response.status
			});
		}
		return {
			accessToken: body.access_token as string,
			idToken: body.id_token as string,
			tokenType: body.token_type as string,
			expiresIn: body.expires_in as number,
			scope: body.scope as string
		};
	}

	/** GET {apiBaseUrl}/api/v1/oauth/userinfo/ — real claims (sub, name, email, picture,
	 * roles, permissions, ...), recomputed live by the backend on every call, never cached
	 * here. Throws TokenExpiredError on any non-2xx response: OneHux Accounts access tokens
	 * are a 15-minute, single-issue lifetime with no refresh token today, so an expired/
	 * invalid token here means "send the user through startAuthorization() again," not
	 * "retry." */
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
}
