/**
 * SvelteKit Adapter
 *
 * First-class integration for SvelteKit applications.
 *
 * @module @tinyland/auth/sveltekit
 */
export { setSessionCookie, setAuthDataCookie, clearSessionCookies, getSessionIdFromCookies, sessionConfigToCookieConfig, type CookieConfig, DEFAULT_COOKIE_CONFIG, } from './session-cookies.js';
export { requireAuth, requireRole, requirePermission, adminGuard, canManageTargetRole, checkAuth, protectEndpoint, getSessionFromLocals, getUserFromLocals, type GuardOptions, type GuardResult, } from './guards.js';
export { createAuthHandle, createCSRFHandle, sequence, getClientIp, type AuthHandleConfig, } from './hook.js';
export { createCSRFStore, csrfStore, getCSRFHeaders, validateCSRF, refreshCSRF, type CSRFState, type CSRFStoreConfig, } from './stores/csrf.svelte.js';
//# sourceMappingURL=index.d.ts.map