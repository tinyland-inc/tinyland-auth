/**
 * SvelteKit Cookie Helpers
 *
 * Secure cookie management for session handling.
 *
 * @module @tinyland/auth/sveltekit
 */
import type { Cookies } from '@sveltejs/kit';
import type { Session, SessionConfig } from '../../types/index.js';
export interface CookieConfig {
    /** Session cookie name */
    sessionCookieName: string;
    /** Auth data cookie name */
    authDataCookieName: string;
    /** Use secure cookies (HTTPS only) */
    secure: boolean;
    /** Cookie path */
    path: string;
    /** SameSite attribute */
    sameSite: 'strict' | 'lax' | 'none';
    /** Cookie max age in seconds */
    maxAge: number;
}
export declare const DEFAULT_COOKIE_CONFIG: CookieConfig;
/**
 * Set session cookie (httpOnly, secure)
 */
export declare function setSessionCookie(cookies: Cookies, sessionId: string, config?: Partial<CookieConfig>): void;
/**
 * Set auth data cookie (client-accessible)
 *
 * Contains non-sensitive session metadata for client use.
 */
export declare function setAuthDataCookie(cookies: Cookies, session: Session, config?: Partial<CookieConfig>): void;
/**
 * Clear all session cookies
 */
export declare function clearSessionCookies(cookies: Cookies, config?: Partial<CookieConfig>): void;
/**
 * Get session ID from cookies
 */
export declare function getSessionIdFromCookies(cookies: Cookies, cookieName?: string): string | undefined;
/**
 * Create cookie config from session config
 */
export declare function sessionConfigToCookieConfig(sessionConfig: SessionConfig): CookieConfig;
//# sourceMappingURL=session-cookies.d.ts.map