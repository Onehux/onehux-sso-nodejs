// src/express.test.ts
// Real integration tests for createOneHuxRouter() against a live Express app (real HTTP, real
// express-session cookie round-trip) — not just unit tests of the framework-agnostic client.
//
// Specifically verifies the propagation path a prior investigation flagged as unconfirmed:
// TokenExpiredError, thrown deep inside OneHuxClient.getUserinfo(), must reach the integrating
// app as a clean, actionable response (GET /auth/userinfo -> 401 with the real error message)
// rather than being silently swallowed by a broad catch somewhere in the middleware chain (e.g.
// caught-and-logged with a 200, or caught and next() called with no error).
//
// Only the call to the upstream OneHux API (apiBaseUrl) is stubbed; the HTTP requests this test
// makes against the local Express app use the real global fetch, so the full real router/
// session/cookie chain runs exactly as it would in production.

import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import express from 'express';
import session from 'express-session';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { createOneHuxRouter } from './express.js';
import { OneHuxClient } from './client.js';

const FAKE_API_BASE_URL = 'https://api.internal.test';

function newTestClient() {
	return new OneHuxClient({
		clientId: 'test-client-id',
		clientSecret: 'test-client-secret',
		redirectUri: 'https://app.example.com/auth/callback',
		postLogoutRedirectUri: 'https://app.example.com/auth/logged-out',
		loginBaseUrl: 'https://accounts.example.com',
		apiBaseUrl: FAKE_API_BASE_URL
	});
}

describe('createOneHuxRouter — TokenExpiredError propagation through Express', () => {
	let server: Server;
	let baseUrl: string;
	let realFetch: typeof fetch;

	beforeEach(async () => {
		realFetch = globalThis.fetch;

		// Intercept only calls aimed at the fake upstream OneHux API; every other fetch (the
		// test's own HTTP requests against the local Express app below) goes through untouched,
		// so the real router/session/cookie plumbing is exercised end to end.
		vi.stubGlobal(
			'fetch',
			vi.fn(async (input: Parameters<typeof fetch>[0], init?: Parameters<typeof fetch>[1]) => {
				const url = typeof input === 'string' ? input : input.toString();
				if (url.startsWith(FAKE_API_BASE_URL)) {
					// Simulates the real /userinfo rejection an expired/revoked access token gets.
					return new Response('', { status: 401 });
				}
				return realFetch(input, init);
			})
		);

		const client = newTestClient();
		const app = express();
		app.use(
			session({
				secret: 'test-session-secret',
				resave: false,
				saveUninitialized: false,
				cookie: { httpOnly: true }
			})
		);
		// Test-only seam: seeds the session with an access token directly, standing in for a
		// completed /auth/callback exchange, so this test can hit /auth/userinfo without driving
		// a full PKCE round-trip against a real hosted login page.
		app.get('/test/seed-session', (req, res) => {
			(req.session as Record<string, unknown>).onehuxAccessToken = 'an-expired-access-token';
			req.session.save(() => res.status(200).end());
		});
		app.use('/auth', createOneHuxRouter(client));

		await new Promise<void>((resolve) => {
			server = createServer(app);
			server.listen(0, '127.0.0.1', resolve);
		});
		const address = server.address() as AddressInfo;
		baseUrl = `http://127.0.0.1:${address.port}`;
	});

	afterEach(async () => {
		vi.unstubAllGlobals();
		await new Promise<void>((resolve) => server.close(() => resolve()));
	});

	it('GET /auth/userinfo: an expired token reaches the app as a 401 with the real error message, never a silent 200', async () => {
		const seedRes = await fetch(`${baseUrl}/test/seed-session`);
		const cookie = seedRes.headers.get('set-cookie')?.split(';')[0];
		expect(cookie).toBeTruthy();

		const res = await fetch(`${baseUrl}/auth/userinfo`, {
			headers: { cookie: cookie as string }
		});

		expect(res.status).toBe(401);
		const body = (await res.json()) as { detail: string };
		expect(body.detail).toMatch(/expired|rejected/i);
	});

	it('GET /auth/userinfo: with no session access token at all, responds 401 without ever calling the client', async () => {
		const res = await fetch(`${baseUrl}/auth/userinfo`);
		expect(res.status).toBe(401);
		const body = (await res.json()) as { detail: string };
		expect(body.detail).toBe('Not signed in.');
	});
});

describe('createOneHuxRouter — transparent refresh-and-retry on /userinfo', () => {
	let server: Server;
	let baseUrl: string;
	let realFetch: typeof fetch;
	let tokenCalls: Array<Record<string, unknown>>;

	async function seedSession(withRefreshToken: string | undefined) {
		const seedRes = await fetch(`${baseUrl}/test/seed-session?refreshToken=${withRefreshToken ?? ''}`);
		const cookie = seedRes.headers.get('set-cookie')?.split(';')[0];
		expect(cookie).toBeTruthy();
		return cookie as string;
	}

	beforeEach(async () => {
		realFetch = globalThis.fetch;
		tokenCalls = [];

		vi.stubGlobal(
			'fetch',
			vi.fn(async (input: Parameters<typeof fetch>[0], init?: Parameters<typeof fetch>[1]) => {
				const url = typeof input === 'string' ? input : input.toString();
				if (!url.startsWith(FAKE_API_BASE_URL)) return realFetch(input, init);

				if (url.endsWith('/api/v1/oauth/userinfo/')) {
					const auth = (init?.headers as Record<string, string> | undefined)?.Authorization ?? '';
					if (auth === 'Bearer a-fresh-access-token') {
						return new Response(JSON.stringify({ sub: 'user-1' }), {
							status: 200,
							headers: { 'Content-Type': 'application/json' }
						});
					}
					return new Response('', { status: 401 });
				}

				if (url.endsWith('/api/v1/oauth/token/')) {
					const body = JSON.parse(init?.body as string) as Record<string, unknown>;
					tokenCalls.push(body);
					if (body.grant_type === 'refresh_token' && body.refresh_token === 'a-live-refresh-token') {
						return new Response(
							JSON.stringify({
								access_token: 'a-fresh-access-token',
								id_token: 'id-refreshed',
								refresh_token: 'a-rotated-refresh-token',
								token_type: 'Bearer',
								expires_in: 900,
								scope: 'openid profile email'
							}),
							{ status: 200, headers: { 'Content-Type': 'application/json' } }
						);
					}
					// Any other refresh_token value (including 'a-dead-refresh-token') is rejected —
					// mirrors the real backend's generic invalid_grant for expiry/reuse/revocation.
					return new Response(
						JSON.stringify({ error: 'invalid_grant', error_description: 'no longer valid' }),
						{ status: 400, headers: { 'Content-Type': 'application/json' } }
					);
				}

				throw new Error(`Unexpected fetch to ${url} in this test`);
			})
		);

		const client = newTestClient();
		const app = express();
		app.use(
			session({
				secret: 'test-session-secret',
				resave: false,
				saveUninitialized: false,
				cookie: { httpOnly: true }
			})
		);
		app.get('/test/seed-session', (req, res) => {
			const session = req.session as Record<string, unknown>;
			session.onehuxAccessToken = 'an-expired-access-token';
			const refreshToken = req.query.refreshToken as string;
			if (refreshToken) session.onehuxSsoRefreshToken = refreshToken;
			req.session.save(() => res.status(200).end());
		});
		app.get('/test/read-session', (req, res) => {
			res.json(req.session as Record<string, unknown>);
		});
		app.use('/auth', createOneHuxRouter(client));

		await new Promise<void>((resolve) => {
			server = createServer(app);
			server.listen(0, '127.0.0.1', resolve);
		});
		const address = server.address() as AddressInfo;
		baseUrl = `http://127.0.0.1:${address.port}`;
	});

	afterEach(async () => {
		vi.unstubAllGlobals();
		await new Promise<void>((resolve) => server.close(() => resolve()));
	});

	it('an expired access token with a live refresh token: silently refreshes and retries, returning real claims', async () => {
		const cookie = await seedSession('a-live-refresh-token');

		const res = await fetch(`${baseUrl}/auth/userinfo`, { headers: { cookie } });

		expect(res.status).toBe(200);
		const claims = (await res.json()) as { sub: string };
		expect(claims.sub).toBe('user-1');
		// Real rotation happened: exactly one refresh_token grant call, with the presented token.
		expect(tokenCalls).toHaveLength(1);
		expect(tokenCalls[0]).toMatchObject({ grant_type: 'refresh_token', refresh_token: 'a-live-refresh-token' });

		// The session now holds the NEW rotated pair, not the old ones — proves the retry path
		// persists rotation correctly rather than reusing the now-dead presented token.
		const sessionRes = await fetch(`${baseUrl}/test/read-session`, { headers: { cookie } });
		const sessionBody = (await sessionRes.json()) as Record<string, unknown>;
		expect(sessionBody.onehuxAccessToken).toBe('a-fresh-access-token');
		expect(sessionBody.onehuxSsoRefreshToken).toBe('a-rotated-refresh-token');
	});

	it('an expired access token with a dead refresh token: 401, and both tokens are cleared from the session', async () => {
		const cookie = await seedSession('a-dead-refresh-token');

		const res = await fetch(`${baseUrl}/auth/userinfo`, { headers: { cookie } });

		expect(res.status).toBe(401);
		const body = (await res.json()) as { detail: string };
		expect(body.detail).toMatch(/sign in again/i);

		const sessionRes = await fetch(`${baseUrl}/test/read-session`, { headers: { cookie } });
		const sessionBody = (await sessionRes.json()) as Record<string, unknown>;
		expect(sessionBody.onehuxAccessToken).toBeUndefined();
		expect(sessionBody.onehuxSsoRefreshToken).toBeUndefined();
	});

	it('an expired access token with no refresh token stored: original behavior, 401 with no refresh attempt', async () => {
		const cookie = await seedSession(undefined);

		const res = await fetch(`${baseUrl}/auth/userinfo`, { headers: { cookie } });

		expect(res.status).toBe(401);
		expect(tokenCalls).toHaveLength(0);
	});
});
