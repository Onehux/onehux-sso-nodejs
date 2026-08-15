// src/index.ts
// Node.js/TypeScript SDK for OneHux Accounts SSO — Authorization Code + PKCE against a real,
// general hosted login page. Formalizes what dashboard/docs/integrate/backend/nodejs's own
// guide otherwise only shows as copy-paste example code.

export { OneHuxClient } from './client.js';
export type { OneHuxClientOptions, PendingAuthorization, TokenResult } from './client.js';
export {
	InvalidStateError,
	OneHuxSSOError,
	TokenExchangeError,
	TokenExpiredError
} from './errors.js';

// Express integration is intentionally NOT re-exported from the root entrypoint — importing
// it requires express/express-session to be installed, and the framework-agnostic OneHuxClient
// above must work standalone without either. Import from 'onehux-sso/express' instead.
