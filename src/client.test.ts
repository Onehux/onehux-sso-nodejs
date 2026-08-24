// src/client.test.ts
// Real unit tests for OneHuxClient — PKCE generation/matching, every error-type branch, every
// URL-building method, and logout_token HMAC verification. No live network calls: global fetch
// is stubbed per test.

import { createHash, createHmac } from 'node:crypto';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { OneHuxClient } from './client.js';
import {
	InvalidStateError,
	OrganizationNotFoundError,
	StepUpRequiredError,
	TokenExchangeError,
	TokenExpiredError
} from './errors.js';

function base64url(buf: Buffer): string {
	return buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function newTestClient(apiBaseUrl = 'https://api.example.com') {
	return new OneHuxClient({
		clientId: 'test-client-id',
		clientSecret: 'test-client-secret',
		redirectUri: 'https://app.example.com/auth/callback',
		postLogoutRedirectUri: 'https://app.example.com/auth/logged-out',
		loginBaseUrl: 'https://accounts.example.com',
		apiBaseUrl
	});
}

function jsonResponse(body: unknown, status = 200): Response {
	return new Response(JSON.stringify(body), {
		status,
		headers: { 'Content-Type': 'application/json' }
	});
}

describe('PKCE generation/matching', () => {
	it('startAuthorization: code_challenge matches sha256(code_verifier)', () => {
		const client = newTestClient();
		const pending = client.startAuthorization();
		expect(pending.codeVerifier).toBeTruthy();
		expect(pending.state).toBeTruthy();

		const url = new URL(pending.authorizationUrl);
		expect(url.searchParams.get('state')).toBe(pending.state);
		expect(url.searchParams.get('code_challenge_method')).toBe('S256');

		const expectedChallenge = base64url(createHash('sha256').update(pending.codeVerifier).digest());
		expect(url.searchParams.get('code_challenge')).toBe(expectedChallenge);
	});

	it('startAuthorization: generates fresh values on each call', () => {
		const client = newTestClient();
		const first = client.startAuthorization();
		const second = client.startAuthorization();
		expect(first.state).not.toBe(second.state);
		expect(first.codeVerifier).not.toBe(second.codeVerifier);
	});
});

describe('exchangeCode error branches', () => {
	beforeEach(() => {
		vi.stubGlobal('fetch', vi.fn());
	});
	afterEach(() => {
		vi.unstubAllGlobals();
	});

	it('throws InvalidStateError on state mismatch', async () => {
		const client = newTestClient();
		await expect(
			client.exchangeCode({ code: 'real-code', state: 'a', expectedState: 'b', codeVerifier: 'v' })
		).rejects.toBeInstanceOf(InvalidStateError);
		expect(fetch).not.toHaveBeenCalled();
	});

	it('throws InvalidStateError on missing code', async () => {
		const client = newTestClient();
		await expect(
			client.exchangeCode({ code: '', state: 's', expectedState: 's', codeVerifier: 'v' })
		).rejects.toBeInstanceOf(InvalidStateError);
	});

	it('throws StepUpRequiredError on step_up_required', async () => {
		vi.mocked(fetch).mockResolvedValueOnce(
			jsonResponse({ error: 'step_up_required', error_description: 'New device or location detected.' }, 403)
		);
		const client = newTestClient();
		let caught: unknown;
		try {
			await client.exchangeCode({ code: 'c', state: 's', expectedState: 's', codeVerifier: 'v' });
		} catch (err) {
			caught = err;
		}
		expect(caught).toBeInstanceOf(StepUpRequiredError);
		expect((caught as StepUpRequiredError).errorDescription).toBe('New device or location detected.');
	});

	it('throws TokenExchangeError on other OAuth errors', async () => {
		vi.mocked(fetch).mockResolvedValueOnce(
			jsonResponse({ error: 'invalid_grant', error_description: 'Authorization code is expired.' }, 400)
		);
		const client = newTestClient();
		let caught: unknown;
		try {
			await client.exchangeCode({ code: 'c', state: 's', expectedState: 's', codeVerifier: 'v' });
		} catch (err) {
			caught = err;
		}
		expect(caught).toBeInstanceOf(TokenExchangeError);
		expect((caught as TokenExchangeError).error).toBe('invalid_grant');
		expect((caught as TokenExchangeError).statusCode).toBe(400);
	});

	it('resolves with tokens on success', async () => {
		vi.mocked(fetch).mockResolvedValueOnce(
			jsonResponse({
				access_token: 'at-123',
				id_token: 'id-456',
				refresh_token: 'rt-789',
				token_type: 'Bearer',
				expires_in: 900,
				scope: 'openid profile email'
			})
		);
		const client = newTestClient();
		const tokens = await client.exchangeCode({ code: 'c', state: 's', expectedState: 's', codeVerifier: 'v' });
		expect(tokens.accessToken).toBe('at-123');
		expect(tokens.refreshToken).toBe('rt-789');
		expect(tokens.expiresIn).toBe(900);
	});
});

describe('getUserinfo', () => {
	beforeEach(() => {
		vi.stubGlobal('fetch', vi.fn());
	});
	afterEach(() => {
		vi.unstubAllGlobals();
	});

	it('throws TokenExpiredError on a non-2xx response', async () => {
		vi.mocked(fetch).mockResolvedValueOnce(new Response('', { status: 401 }));
		const client = newTestClient();
		await expect(client.getUserinfo({ accessToken: 'expired' })).rejects.toBeInstanceOf(TokenExpiredError);
	});
});

describe('refreshAccessToken', () => {
	beforeEach(() => {
		vi.stubGlobal('fetch', vi.fn());
	});
	afterEach(() => {
		vi.unstubAllGlobals();
	});

	it('resolves with a rotated token triple on success, POSTing grant_type=refresh_token', async () => {
		vi.mocked(fetch).mockResolvedValueOnce(
			jsonResponse({
				access_token: 'at-new',
				id_token: 'id-new',
				refresh_token: 'rt-new',
				token_type: 'Bearer',
				expires_in: 900,
				scope: 'openid profile email'
			})
		);
		const client = newTestClient();
		const tokens = await client.refreshAccessToken({ refreshToken: 'rt-old' });

		expect(tokens.accessToken).toBe('at-new');
		expect(tokens.refreshToken).toBe('rt-new');
		expect(fetch).toHaveBeenCalledWith(
			'https://api.example.com/api/v1/oauth/token/',
			expect.objectContaining({ method: 'POST' })
		);
		const [, init] = vi.mocked(fetch).mock.calls[0];
		const body = JSON.parse((init as RequestInit).body as string);
		expect(body).toMatchObject({
			grant_type: 'refresh_token',
			refresh_token: 'rt-old',
			client_id: 'test-client-id',
			client_secret: 'test-client-secret'
		});
	});

	it('throws TokenExpiredError on a non-2xx response (expired, reuse-detected, or revoked — indistinguishable by design)', async () => {
		vi.mocked(fetch).mockResolvedValueOnce(
			jsonResponse({ error: 'invalid_grant', error_description: 'Refresh token is no longer valid.' }, 400)
		);
		const client = newTestClient();
		await expect(client.refreshAccessToken({ refreshToken: 'rt-dead' })).rejects.toBeInstanceOf(
			TokenExpiredError
		);
	});
});

describe('getPublicApplications', () => {
	beforeEach(() => {
		vi.stubGlobal('fetch', vi.fn());
	});
	afterEach(() => {
		vi.unstubAllGlobals();
	});

	it('returns typed applications on success', async () => {
		vi.mocked(fetch).mockResolvedValueOnce(
			jsonResponse([{ name: 'ODS', logo_url: 'https://example.com/logo.png', home_url: 'https://ods.example.com' }])
		);
		const client = newTestClient();
		const apps = await client.getPublicApplications({ orgSlug: 'onehux' });
		expect(apps).toEqual([
			{ name: 'ODS', logoUrl: 'https://example.com/logo.png', homeUrl: 'https://ods.example.com' }
		]);
		expect(fetch).toHaveBeenCalledWith(
			'https://api.example.com/api/v1/organizations/onehux/public-applications/'
		);
	});

	it('throws OrganizationNotFoundError on 404', async () => {
		vi.mocked(fetch).mockResolvedValueOnce(
			jsonResponse({ error: 'not_found', error_description: 'No Organization matches that slug.' }, 404)
		);
		const client = newTestClient();
		await expect(client.getPublicApplications({ orgSlug: 'nope' })).rejects.toBeInstanceOf(
			OrganizationNotFoundError
		);
	});
});

describe('URL-building methods', () => {
	it('buildLogoutUrl: correct host/params, no state when omitted', () => {
		const client = newTestClient();
		const url = new URL(client.buildLogoutUrl());
		expect(url.origin + url.pathname).toBe('https://accounts.example.com/end-session');
		expect(url.searchParams.get('client_id')).toBe('test-client-id');
		expect(url.searchParams.get('post_logout_redirect_uri')).toBe('https://app.example.com/auth/logged-out');
		expect(url.searchParams.has('state')).toBe(false);
	});

	it('buildLogoutUrl: includes state when given', () => {
		const client = newTestClient();
		const url = new URL(client.buildLogoutUrl({ state: 'xyz' }));
		expect(url.searchParams.get('state')).toBe('xyz');
	});

	it('buildStepUpRedirectUrl: correct host/path/params and re-derived code_challenge', () => {
		const client = newTestClient();
		const codeVerifier = 'abc123verifier';
		const url = new URL(client.buildStepUpRedirectUrl({ codeVerifier, state: 'state-xyz' }));
		expect(url.origin + url.pathname).toBe('https://accounts.example.com/login/email-otp');
		expect(url.searchParams.get('reason')).toBe('step_up');
		expect(url.searchParams.get('client_id')).toBe('test-client-id');
		expect(url.searchParams.get('redirect_uri')).toBe('https://app.example.com/auth/callback');
		expect(url.searchParams.get('state')).toBe('state-xyz');

		const expectedChallenge = base64url(createHash('sha256').update(codeVerifier).digest());
		expect(url.searchParams.get('code_challenge')).toBe(expectedChallenge);
	});
});

describe('verifyLogoutToken (logout_token HMAC verification)', () => {
	function buildToken(secret: string, claims: Record<string, unknown>): string {
		const header = { alg: 'HS256', typ: 'logout+jwt' };
		const headerB64 = base64url(Buffer.from(JSON.stringify(header)));
		const payloadB64 = base64url(Buffer.from(JSON.stringify(claims)));
		const sig = base64url(createHmac('sha256', secret).update(`${headerB64}.${payloadB64}`).digest());
		return `${headerB64}.${payloadB64}.${sig}`;
	}

	function validClaims(): Record<string, unknown> {
		return {
			iss: 'https://accounts.onehux.com',
			aud: 'test-client-id',
			iat: Math.floor(Date.now() / 1000),
			exp: Math.floor(Date.now() / 1000) + 120,
			jti: 'unique-id',
			events: { 'http://schemas.openid.net/event/backchannel-logout': {} },
			sid: 'session-123'
		};
	}

	it('accepts a valid token', () => {
		const client = newTestClient();
		const token = buildToken('shared-secret', validClaims());
		const payload = client.verifyLogoutToken({ logoutToken: token, signingSecret: 'shared-secret' });
		expect(payload.sid).toBe('session-123');
	});

	it('rejects a token signed with the wrong secret', () => {
		const client = newTestClient();
		const token = buildToken('shared-secret', validClaims());
		expect(() => client.verifyLogoutToken({ logoutToken: token, signingSecret: 'wrong-secret' })).toThrow();
	});

	it('rejects an expired token', () => {
		const client = newTestClient();
		const claims = validClaims();
		claims.exp = Math.floor(Date.now() / 1000) - 60;
		const token = buildToken('shared-secret', claims);
		expect(() => client.verifyLogoutToken({ logoutToken: token, signingSecret: 'shared-secret' })).toThrow();
	});

	it('rejects a token with the wrong audience', () => {
		const client = newTestClient();
		const claims = validClaims();
		claims.aud = 'some-other-client';
		const token = buildToken('shared-secret', claims);
		expect(() => client.verifyLogoutToken({ logoutToken: token, signingSecret: 'shared-secret' })).toThrow();
	});

	it('rejects a token with a nonce claim present', () => {
		const client = newTestClient();
		const claims = validClaims();
		claims.nonce = 'should-not-be-here';
		const token = buildToken('shared-secret', claims);
		expect(() => client.verifyLogoutToken({ logoutToken: token, signingSecret: 'shared-secret' })).toThrow();
	});

	it('rejects a token missing the events claim', () => {
		const client = newTestClient();
		const claims = validClaims();
		delete claims.events;
		const token = buildToken('shared-secret', claims);
		expect(() => client.verifyLogoutToken({ logoutToken: token, signingSecret: 'shared-secret' })).toThrow();
	});

	it('rejects a token missing both sub and sid', () => {
		const client = newTestClient();
		const claims = validClaims();
		delete claims.sid;
		const token = buildToken('shared-secret', claims);
		expect(() => client.verifyLogoutToken({ logoutToken: token, signingSecret: 'shared-secret' })).toThrow();
	});
});
