/**
 * SvelteKit Adapter
 *
 * First-class integration for SvelteKit applications.
 *
 * @module @tinyland/auth/sveltekit
 */

// Cookie helpers
export {
  setSessionCookie,
  setAuthDataCookie,
  clearSessionCookies,
  getSessionIdFromCookies,
  sessionConfigToCookieConfig,
  type CookieConfig,
  DEFAULT_COOKIE_CONFIG,
} from './session-cookies.js';

// Route guards
export {
  requireAuth,
  requireRole,
  requirePermission,
  adminGuard,
  canManageTargetRole,
  checkAuth,
  protectEndpoint,
  getSessionFromLocals,
  getUserFromLocals,
  type GuardOptions,
  type GuardResult,
} from './guards.js';

// Server hook
export {
  createAuthHandle,
  createCSRFHandle,
  sequence,
  getClientIp,
  type AuthHandleConfig,
} from './hook.js';

// CSRF Store (Svelte 5 runes)
export {
  createCSRFStore,
  csrfStore,
  getCSRFHeaders,
  validateCSRF,
  refreshCSRF,
  type CSRFState,
  type CSRFStoreConfig,
} from './stores/csrf.svelte.js';

// Ownership guards (SvelteKit wrappers)
export {
  requireContentEditPermission,
  requireContentDeletePermission,
  isContentOwner,
  canEditOwnedContent,
  canDeleteOwnedContent,
  isSoleOwner,
  type OwnershipUser,
  type OwnedContent,
} from './ownership.js';

// mTLS adapter (SvelteKit wrappers)
export {
  extractCertificateFromEvent,
  requireMTLS,
  getCertificateFingerprintFromEvent,
  type CertificateHeaders,
  type CertificateInfo,
  type MTLSOptions,
} from './mtls.js';
