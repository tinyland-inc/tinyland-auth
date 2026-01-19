/**
 * SvelteKit Adapter
 *
 * First-class integration for SvelteKit applications.
 *
 * @module @tinyland/auth/sveltekit
 */
// Cookie helpers
export { setSessionCookie, setAuthDataCookie, clearSessionCookies, getSessionIdFromCookies, sessionConfigToCookieConfig, DEFAULT_COOKIE_CONFIG, } from './session-cookies.js';
// Route guards
export { requireAuth, requireRole, requirePermission, adminGuard, canManageTargetRole, checkAuth, protectEndpoint, getSessionFromLocals, getUserFromLocals, } from './guards.js';
// Server hook
export { createAuthHandle, createCSRFHandle, sequence, getClientIp, } from './hook.js';
// CSRF Store (Svelte 5 runes)
export { createCSRFStore, csrfStore, getCSRFHeaders, validateCSRF, refreshCSRF, } from './stores/csrf.svelte.js';
//# sourceMappingURL=index.js.map