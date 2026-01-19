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
/**
 * CSRF state interface
 */
export interface CSRFState {
    token: string | null;
    tokenHash: string | null;
    issuedAt: number | null;
    expiresAt: number | null;
    role: string | null;
}
/**
 * CSRF store configuration
 */
export interface CSRFStoreConfig {
    /** Header name for CSRF token */
    headerName: string;
    /** Cookie name for CSRF token */
    cookieName: string;
    /** Token lifetime in milliseconds */
    tokenLifetimeMs: number;
    /** Refresh threshold before expiry in milliseconds */
    refreshThresholdMs: number;
    /** API endpoint for token operations */
    tokenEndpoint: string;
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
export declare function createCSRFStore(config?: Partial<CSRFStoreConfig>): {
    readonly token: string | null;
    readonly isValid: boolean;
    readonly isExpiringSoon: boolean;
    readonly role: string | null;
    readonly timeUntilExpiry: number | null;
    readonly expiresAt: number | null;
    initialize: (token: string, role?: string) => void;
    fetchToken: () => Promise<string | null>;
    rotateOnRoleChange: (newRole: string) => Promise<void>;
    refreshIfNeeded: () => Promise<void>;
    getHeaders: () => Record<string, string>;
    validate: (token: string) => boolean;
    clear: () => void;
    setRole: (role: string | null) => void;
    config: {
        headerName: string;
        cookieName: string;
        tokenLifetimeMs: number;
        refreshThresholdMs: number;
        tokenEndpoint: string;
    };
};
/**
 * Default singleton CSRF store instance
 */
export declare const csrfStore: {
    readonly token: string | null;
    readonly isValid: boolean;
    readonly isExpiringSoon: boolean;
    readonly role: string | null;
    readonly timeUntilExpiry: number | null;
    readonly expiresAt: number | null;
    initialize: (token: string, role?: string) => void;
    fetchToken: () => Promise<string | null>;
    rotateOnRoleChange: (newRole: string) => Promise<void>;
    refreshIfNeeded: () => Promise<void>;
    getHeaders: () => Record<string, string>;
    validate: (token: string) => boolean;
    clear: () => void;
    setRole: (role: string | null) => void;
    config: {
        headerName: string;
        cookieName: string;
        tokenLifetimeMs: number;
        refreshThresholdMs: number;
        tokenEndpoint: string;
    };
};
export declare const getCSRFHeaders: () => Record<string, string>;
export declare const validateCSRF: (token: string) => boolean;
export declare const refreshCSRF: () => Promise<void>;
//# sourceMappingURL=csrf.svelte.d.ts.map