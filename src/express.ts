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
import { Router } from 'express';
import { OneHuxClient } from './client.js';
import { InvalidStateError, TokenExchangeError, TokenExpiredError } from './errors.js';

const STATE_SESSION_KEY = 'onehuxSsoState';
const VERIFIER_SESSION_KEY = 'onehuxSsoPkceVerifier';

export interface OneHuxRouterOptions {
	/** Session key the access token is stored under. Default: 'onehuxAccessToken'. */
	sessionAccessTokenKey?: string;
	/** Path to redirect to after a successful login. Default: '/'. */
	loginSuccessRedirect?: string;
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
			res.status(400).send(`Sign-in failed: ${error} — ${errorDescription ?? ''}`);
			return;
		}

		const session = req.session as Record<string, unknown>;
		const expectedState = session[STATE_SESSION_KEY] as string | undefined;
		const codeVerifier = session[VERIFIER_SESSION_KEY] as string | undefined;
		delete session[STATE_SESSION_KEY];
		delete session[VERIFIER_SESSION_KEY];

		try {
			const tokens = await client.exchangeCode({
				code: code ?? '',
				state: state ?? '',
				expectedState,
				codeVerifier
			});
			session[sessionAccessTokenKey] = tokens.accessToken;
			res.redirect(loginSuccessRedirect);
		} catch (err) {
			if (err instanceof InvalidStateError) {
				res.status(400).send(err.message);
				return;
			}
			if (err instanceof TokenExchangeError) {
				res.status(400).send(`${err.error}: ${err.errorDescription}`);
				return;
			}
			throw err;
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
			throw err;
		}
	});

	return router;
}
