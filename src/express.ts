// src/express.ts
// createOneHuxRouter() — wires OneHuxClient to a real Express session (express-session), the
// same BFF discipline the platform's own dashboard follows on itself: the access token lives
// server-side only, in the session store, never sent to the browser. Optional: use
// OneHuxClient directly if you'd rather wire your own routes (see the README).
//
// express and express-session are peer dependencies, not bundled — this file only imports
// their types, so consumers who only want the framework-agnostic OneHuxClient never need to
// install Express at all.

import type { Request, Response, Router as ExpressRouter } from 'express';
import express, { Router } from 'express';
import { OneHuxClient } from './client.js';
import {
	InvalidLogoutTokenError,
	InvalidStateError,
	StepUpRequiredError,
	TokenExchangeError,
	TokenExpiredError
} from './errors.js';

const STATE_SESSION_KEY = 'onehuxSsoState';
const VERIFIER_SESSION_KEY = 'onehuxSsoPkceVerifier';
const SID_SESSION_KEY = 'onehuxSsoSid';

/** Pluggable sid -> Express session-id index (OIDC Back-Channel Logout). A logout_token POST
 * carries the OneHux Session id (`sid`) but nothing about which local Express session that
 * corresponds to — this index is what bridges the two. The default InMemorySidIndex is correct
 * for a single-process dev/example app only; a real multi-process deployment must supply a
 * shared implementation (Redis, etc.) backed by the same store your session middleware uses,
 * so every process instance can resolve a sid regardless of which one originally handled the
 * login. */
export interface BackchannelSidIndex {
	set(sid: string, sessionId: string): void | Promise<void>;
	get(sid: string): string | undefined | Promise<string | undefined>;
	delete(sid: string): void | Promise<void>;
}

class InMemorySidIndex implements BackchannelSidIndex {
	private readonly map = new Map<string, string>();
	set(sid: string, sessionId: string): void {
		this.map.set(sid, sessionId);
	}
	get(sid: string): string | undefined {
		return this.map.get(sid);
	}
	delete(sid: string): void {
		this.map.delete(sid);
	}
}

export interface OneHuxRouterOptions {
	/** Session key the access token is stored under. Default: 'onehuxAccessToken'. */
	sessionAccessTokenKey?: string;
	/** Path to redirect to after a successful login. Default: '/'. */
	loginSuccessRedirect?: string;
	/** The dedicated signing secret shown once when you registered your backchannel_logout_uri
	 * via PATCH /api/v1/applications/{id}/backchannel-logout/ — deliberately NOT clientSecret.
	 * Required only if you want the /backchannel-logout route to actually verify and act on
	 * incoming logout_token POSTs; if omitted, that route responds 400 to every request rather
	 * than silently accepting an unverifiable one. */
	backchannelLogoutSigningSecret?: string;
	/** sid -> Express session-id index. Defaults to an in-memory Map, correct for a single-
	 * process dev/example app only — see BackchannelSidIndex's own docstring. */
	sidIndex?: BackchannelSidIndex;
}

declare module 'express-session' {
	interface SessionData {
		[key: string]: unknown;
	}
}

/** Mounts /login, /callback, /logout, /userinfo relative to wherever you `app.use(prefix,
 * router)` this — e.g. `app.use('/auth', createOneHuxRouter(client))` gives you
 * /auth/login, /auth/callback, /auth/logout, /auth/userinfo. Requires express-session (or a
 * compatible req.session) to already be installed as app-level middleware before this router
 * runs. */
export function createOneHuxRouter(
	client: OneHuxClient,
	options: OneHuxRouterOptions = {}
): ExpressRouter {
	const sessionAccessTokenKey = options.sessionAccessTokenKey ?? 'onehuxAccessToken';
	const loginSuccessRedirect = options.loginSuccessRedirect ?? '/';
	const backchannelLogoutSigningSecret = options.backchannelLogoutSigningSecret;
	const sidIndex: BackchannelSidIndex = options.sidIndex ?? new InMemorySidIndex();

	const router: ExpressRouter = Router();

	router.get('/login', (req: Request, res: Response) => {
		const pending = client.startAuthorization();
		(req.session as Record<string, unknown>)[STATE_SESSION_KEY] = pending.state;
		(req.session as Record<string, unknown>)[VERIFIER_SESSION_KEY] = pending.codeVerifier;
		res.redirect(pending.authorizationUrl);
	});

	router.get('/callback', async (req: Request, res: Response) => {
		const { code, state, error, error_description: errorDescription } = req.query as Record<
			string,
			string | undefined
		>;
		if (error) {
			const session = req.session as Record<string, unknown>;
			delete session[STATE_SESSION_KEY];
			delete session[VERIFIER_SESSION_KEY];
			res.status(400).send(`Sign-in failed: ${error} — ${errorDescription ?? ''}`);
			return;
		}

		// Peeked, not deleted here: the step_up_required branch below needs these to still be in
		// the session if it fires. Every other branch (success, InvalidStateError, any other
		// TokenExchangeError) deletes them explicitly before returning — this is a narrow,
		// additive branch, not a change to the general discard behavior.
		const session = req.session as Record<string, unknown>;
		const expectedState = session[STATE_SESSION_KEY] as string | undefined;
		const codeVerifier = session[VERIFIER_SESSION_KEY] as string | undefined;

		try {
			const tokens = await client.exchangeCode({
				code: code ?? '',
				state: state ?? '',
				expectedState,
				codeVerifier
			});
			delete session[STATE_SESSION_KEY];
			delete session[VERIFIER_SESSION_KEY];
			session[sessionAccessTokenKey] = tokens.accessToken;

			// OIDC Back-Channel Logout (optional): index this Express session by the OneHux
			// Session id (`sid`) carried in the id_token, so a later logout_token POST to
			// /backchannel-logout can find and destroy exactly this session.
			const sid = client.extractSidFromIdToken(tokens.idToken);
			if (sid && req.sessionID) {
				session[SID_SESSION_KEY] = sid;
				await sidIndex.set(sid, req.sessionID);
			}

			res.redirect(loginSuccessRedirect);
		} catch (err) {
			if (err instanceof InvalidStateError) {
				delete session[STATE_SESSION_KEY];
				delete session[VERIFIER_SESSION_KEY];
				res.status(400).send(err.message);
				return;
			}
			if (err instanceof StepUpRequiredError) {
				if (!codeVerifier || !state) {
					res.status(400).send('step_up_required with no pending PKCE state to resume.');
					return;
				}
				res.redirect(client.buildStepUpRedirectUrl({ codeVerifier, state }));
				return;
			}
			if (err instanceof TokenExchangeError) {
				delete session[STATE_SESSION_KEY];
				delete session[VERIFIER_SESSION_KEY];
				res.status(400).send(`${err.error}: ${err.errorDescription}`);
				return;
			}
			// Anything else (a raw network failure talking to apiBaseUrl, a timeout, etc.) is
			// deliberately NOT re-thrown: an unhandled rejection inside an async Express route
			// takes down the entire process, not just this request, if nothing else catches it.
			// A transient failure reaching OneHux must degrade to one failed sign-in attempt, not
			// crash the whole app for every other user's request in flight. Never forward the raw
			// error to the browser either — log it server-side, same discipline as every other
			// backend error boundary in this project.
			console.error('OneHux SSO: unexpected error during token exchange:', err);
			delete session[STATE_SESSION_KEY];
			delete session[VERIFIER_SESSION_KEY];
			res.status(502).send('Sign-in temporarily unavailable. Please try again.');
		}
	});

	router.get('/logout', (req: Request, res: Response) => {
		delete (req.session as Record<string, unknown>)[sessionAccessTokenKey];
		res.redirect(client.buildLogoutUrl());
	});

	router.get('/userinfo', async (req: Request, res: Response) => {
		const accessToken = (req.session as Record<string, unknown>)[sessionAccessTokenKey] as
			| string
			| undefined;
		if (!accessToken) {
			res.status(401).json({ detail: 'Not signed in.' });
			return;
		}
		try {
			const claims = await client.getUserinfo({ accessToken });
			res.json(claims);
		} catch (err) {
			if (err instanceof TokenExpiredError) {
				res.status(401).json({ detail: err.message });
				return;
			}
			// Same reasoning as the /callback route: never re-throw an unrecognized error out of
			// an async Express handler, or a transient network failure crashes the whole process.
			console.error('OneHux SSO: unexpected error during userinfo lookup:', err);
			res.status(502).json({ detail: 'Unable to reach OneHux right now. Please try again.' });
		}
	});

	// OIDC Back-Channel Logout receiving endpoint (spec: openid-connect-backchannel-1_0 §2.6).
	// Register this exact URL (e.g. https://yourapp.example.com/auth/backchannel-logout) via
	// PATCH /api/v1/applications/{id}/backchannel-logout/ on OneHux. This is what makes an
	// IdP-initiated logout (a user clicking "log out" directly on accounts.onehux.com, or an
	// admin revoking their session) actually terminate THIS app's own local Express session in
	// real time, rather than only being discovered the next time this app happens to call
	// /userinfo and gets a 401. The platform-side session is genuinely revoked immediately
	// either way — without this route mounted and registered, only the notification is missing.
	//
	// express.urlencoded() body parsing is scoped to this route only, per spec: the OP POSTs
	// application/x-www-form-urlencoded with a single logout_token field, not JSON. No CSRF
	// protection is applied (and none should be) — this is a server-to-server POST from
	// OneHux's own backend with no browser session/cookie of its own to carry a CSRF token; the
	// logout_token's own HS256 signature (verified below) is this route's real authenticity
	// check.
	router.post(
		'/backchannel-logout',
		express.urlencoded({ extended: false }),
		async (req: Request, res: Response) => {
			res.set('Cache-Control', 'no-store');

			const logoutToken = (req.body as Record<string, unknown> | undefined)?.logout_token;
			if (typeof logoutToken !== 'string' || !logoutToken) {
				res.status(400).json({ error: 'invalid_request', error_description: 'Missing logout_token.' });
				return;
			}
			if (!backchannelLogoutSigningSecret) {
				res.status(400).json({
					error: 'invalid_request',
					error_description:
						'This app has not configured backchannelLogoutSigningSecret — cannot verify logout_token.'
				});
				return;
			}

			let payload;
			try {
				payload = client.verifyLogoutToken({
					logoutToken,
					signingSecret: backchannelLogoutSigningSecret
				});
			} catch (err) {
				if (err instanceof InvalidLogoutTokenError) {
					res.status(400).json({ error: 'invalid_request', error_description: err.message });
					return;
				}
				throw err;
			}

			// A miss here (already logged out locally, or this process never saw the login) is
			// a correct, spec-defined success case (§2.6: "the logout is considered to have
			// succeeded"), not an error — still responds 200 below.
			if (payload.sid) {
				const sessionId = await sidIndex.get(payload.sid);
				if (sessionId) {
					await new Promise<void>((resolve) => {
						req.sessionStore.destroy(sessionId, () => resolve());
					});
					await sidIndex.delete(payload.sid);
				}
			}

			res.status(200).end();
		}
	);

	return router;
}
