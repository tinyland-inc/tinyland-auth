/**
 * CSRF Token Store - Svelte 5 Runes Implementation
 *
 * Client-side reactive store for CSRF protection with:
 * - Automatic token rotation on role change
 * - Token expiration tracking and auto-refresh
 * - Session-aware token management
 *
 * @module @tinyland/auth/sveltekit/stores/csrf
 */
const DEFAULT_CONFIG = {
    headerName: 'x-csrf-token',
    cookieName: 'csrf_token',
    tokenLifetimeMs: 24 * 60 * 60 * 1000, // 24 hours
    refreshThresholdMs: 30 * 60 * 1000, // 30 minutes
    tokenEndpoint: '/api/csrf-token',
};
/**
 * Simple hash for token comparison (not cryptographic)
 * Used for cache-busting and change detection
 */
function hashToken(token) {
    let hash = 0;
    for (let i = 0; i < token.length; i++) {
        const char = token.charCodeAt(i);
        hash = ((hash << 5) - hash) + char;
        hash = hash & hash;
    }
    return hash.toString(16);
}
/**
 * Read token from cookie
 */
function readTokenFromCookie(cookieName) {
    if (typeof document === 'undefined')
        return null;
    const cookies = document.cookie.split(';').map((c) => c.trim());
    const csrfCookie = cookies.find((c) => c.startsWith(`${cookieName}=`));
    if (csrfCookie) {
        const token = csrfCookie.split('=')[1];
        return decodeURIComponent(token);
    }
    return null;
}
/**
 * Create CSRF store with Svelte 5 runes
 *
 * @example
 * ```typescript
 * import { createCSRFStore } from '@tinyland/auth/sveltekit';
 *
 * const csrf = createCSRFStore();
 *
 * // Initialize on mount
 * $effect(() => {
 *   csrf.fetchToken();
 * });
 *
 * // Use in fetch
 * const response = await fetch('/api/data', {
 *   method: 'POST',
 *   headers: csrf.getHeaders(),
 * });
 * ```
 */
export function createCSRFStore(config = {}) {
    const cfg = { ...DEFAULT_CONFIG, ...config };
    // Reactive state using Svelte 5 runes
    let state = $state({
        token: null,
        tokenHash: null,
        issuedAt: null,
        expiresAt: null,
        role: null,
    });
    // Derived state
    const isValid = $derived(state.token !== null &&
        state.expiresAt !== null &&
        Date.now() < state.expiresAt);
    const isExpiringSoon = $derived(state.expiresAt !== null &&
        Date.now() > state.expiresAt - cfg.refreshThresholdMs);
    const timeUntilExpiry = $derived(state.expiresAt !== null
        ? Math.max(0, state.expiresAt - Date.now())
        : null);
    /**
     * Initialize token from server response or cookie
     */
    function initialize(token, role) {
        const now = Date.now();
        state = {
            token,
            tokenHash: hashToken(token),
            issuedAt: now,
            expiresAt: now + cfg.tokenLifetimeMs,
            role: role ?? null,
        };
    }
    /**
     * Fetch fresh token from server
     */
    async function fetchToken() {
        try {
            // First try to read from cookie
            const cookieToken = readTokenFromCookie(cfg.cookieName);
            if (cookieToken) {
                initialize(cookieToken);
                return cookieToken;
            }
            // If no cookie, request new token from server
            const response = await fetch(cfg.tokenEndpoint, {
                method: 'GET',
                credentials: 'include',
            });
            if (response.ok) {
                const data = await response.json();
                if (data.token) {
                    initialize(data.token);
                    return data.token;
                }
            }
        }
        catch (error) {
            console.error('[CSRF Store] Failed to fetch token:', error);
        }
        return null;
    }
    /**
     * Rotate token on role change
     */
    async function rotateOnRoleChange(newRole) {
        if (state.role === newRole) {
            return;
        }
        console.log(`[CSRF Store] Rotating token due to role change: ${state.role} → ${newRole}`);
        try {
            const response = await fetch(cfg.tokenEndpoint, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                credentials: 'include',
                body: JSON.stringify({
                    reason: 'role_change',
                    previousRole: state.role,
                    newRole,
                }),
            });
            if (response.ok) {
                const data = await response.json();
                if (data.token) {
                    initialize(data.token, newRole);
                    console.log('[CSRF Store] Token rotated successfully');
                }
            }
            else {
                console.error('[CSRF Store] Failed to rotate token:', response.status);
            }
        }
        catch (error) {
            console.error('[CSRF Store] Token rotation error:', error);
        }
    }
    /**
     * Auto-refresh if token is expiring soon
     */
    async function refreshIfNeeded() {
        if (!isExpiringSoon)
            return;
        console.log('[CSRF Store] Token expiring soon, refreshing');
        try {
            const response = await fetch(cfg.tokenEndpoint, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                credentials: 'include',
                body: JSON.stringify({ reason: 'refresh' }),
            });
            if (response.ok) {
                const data = await response.json();
                if (data.token) {
                    initialize(data.token, state.role ?? undefined);
                    console.log('[CSRF Store] Token refreshed successfully');
                }
            }
        }
        catch (error) {
            console.error('[CSRF Store] Token refresh error:', error);
        }
    }
    /**
     * Get headers for fetch requests
     */
    function getHeaders() {
        if (!state.token || !isValid) {
            console.warn('[CSRF Store] No valid token available for request');
            return {};
        }
        return { [cfg.headerName]: state.token };
    }
    /**
     * Validate token matches expected value
     */
    function validate(token) {
        if (!state.token)
            return false;
        return token === state.token && isValid;
    }
    /**
     * Clear token (on logout)
     */
    function clear() {
        console.log('[CSRF Store] Clearing token');
        state = {
            token: null,
            tokenHash: null,
            issuedAt: null,
            expiresAt: null,
            role: null,
        };
    }
    /**
     * Update role without rotating token
     */
    function setRole(role) {
        state.role = role;
    }
    return {
        // Reactive state (read-only getters)
        get token() { return state.token; },
        get isValid() { return isValid; },
        get isExpiringSoon() { return isExpiringSoon; },
        get role() { return state.role; },
        get timeUntilExpiry() { return timeUntilExpiry; },
        get expiresAt() { return state.expiresAt; },
        // Actions
        initialize,
        fetchToken,
        rotateOnRoleChange,
        refreshIfNeeded,
        getHeaders,
        validate,
        clear,
        setRole,
        // Configuration
        config: cfg,
    };
}
/**
 * Default singleton CSRF store instance
 */
export const csrfStore = createCSRFStore();
// Convenience exports
export const getCSRFHeaders = () => csrfStore.getHeaders();
export const validateCSRF = (token) => csrfStore.validate(token);
export const refreshCSRF = () => csrfStore.refreshIfNeeded();
//# sourceMappingURL=csrf.svelte.js.map