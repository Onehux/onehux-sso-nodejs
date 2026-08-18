// Real, runnable example — exercises onehux-sso end to end against production. Uses
// createOneHuxRouter() for the four standard routes, plus its own home/logged-out pages.

import express from 'express';
import session from 'express-session';
import crypto from 'node:crypto';
import { OneHuxClient, TokenExpiredError } from 'onehux-sso';
import { createOneHuxRouter } from 'onehux-sso/express';

const PORT = Number(process.env.PORT || 4182);
const CLIENT_ID = process.env.ONEHUX_CLIENT_ID;
const CLIENT_SECRET = process.env.ONEHUX_CLIENT_SECRET;

if (!CLIENT_ID || !CLIENT_SECRET) {
	console.error('Missing ONEHUX_CLIENT_ID / ONEHUX_CLIENT_SECRET env vars.');
	process.exit(1);
}

const client = new OneHuxClient({
	clientId: CLIENT_ID,
	clientSecret: CLIENT_SECRET,
	redirectUri: `http://localhost:${PORT}/auth/callback`,
	postLogoutRedirectUri: `http://localhost:${PORT}/auth/logged-out`
});

const app = express();
app.use(
	session({
		secret: process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex'),
		resave: false,
		saveUninitialized: false,
		cookie: { httpOnly: true, sameSite: 'lax' }
	})
);
app.use(
	'/auth',
	createOneHuxRouter(client, {
		// OIDC Back-Channel Logout (README.md ADR-074, backend repo) — the dedicated secret
		// shown once by PATCH /api/v1/applications/{id}/backchannel-logout/, NOT clientSecret.
		backchannelLogoutSigningSecret: process.env.ONEHUX_BACKCHANNEL_LOGOUT_SIGNING_SECRET
	})
);

function page(body) {
	return `<!doctype html><html><head><meta charset="utf-8"><title>onehux-sso example</title>
<style>body{font-family:system-ui,sans-serif;max-width:640px;margin:3rem auto;padding:0 1rem;color:#111}
a.btn{display:inline-block;padding:.5rem 1rem;border:1px solid #333;border-radius:4px;text-decoration:none;color:#111;margin-right:.5rem}
pre{background:#f4f4f4;padding:1rem;overflow-x:auto;white-space:pre-wrap}</style></head>
<body>${body}</body></html>`;
}

app.get('/', async (req, res) => {
	const accessToken = req.session.onehuxAccessToken;
	if (!accessToken) {
		return res.send(
			page(`
			<h1>onehux-sso example — signed out</h1>
			<p>Real end-to-end demo of the onehux-sso npm package against production.</p>
			<a class="btn" href="/auth/login">Sign in</a>
		`)
		);
	}

	try {
		const claims = await client.getUserinfo({ accessToken });
		res.send(
			page(`
			<h1>onehux-sso example — signed in</h1>
			<p>Real claims from GET /api/v1/oauth/userinfo/:</p>
			<pre>${JSON.stringify(claims, null, 2)}</pre>
			<a class="btn" href="/auth/logout">Log out (RP-initiated SLO)</a>
			<p style="margin-top:2rem;color:#666">To confirm true single-logout, separately open
			<a href="https://accounts.onehux.com/dashboard" target="_blank">accounts.onehux.com/dashboard</a>
			after logging out — it should demand login again.</p>
		`)
		);
	} catch (err) {
		if (err instanceof TokenExpiredError) {
			return res
				.status(401)
				.send(page(`<h1>Token expired</h1><pre>${err.message}</pre><a class="btn" href="/auth/login">Sign in again</a>`));
		}
		// Same reasoning as onehux-sso's own /auth/userinfo route: never re-throw an
		// unrecognized error (e.g. a transient network failure reaching OneHux) out of an
		// async Express handler, or it crashes this whole example server, not just one request.
		console.error('onehux-sso example: unexpected error calling getUserinfo:', err);
		res
			.status(502)
			.send(page(`<h1>Temporarily unavailable</h1><p>Could not reach OneHux right now. Please try again.</p><a class="btn" href="/">Retry</a>`));
	}
});

app.get('/auth/logged-out', (req, res) => {
	res.send(
		page(`
		<h1>Logged out</h1>
		<p>Redirected back here by OneHux's own RP-initiated logout.</p>
		<a class="btn" href="/">Home</a>
	`)
	);
});

app.listen(PORT, () => {
	console.log(`onehux-sso example listening on http://localhost:${PORT}`);
});
