/**
 * SvelteKit Cookie Helpers
 *
 * Secure cookie management for session handling.
 *
 * @module @tinyland/auth/sveltekit
 */
export const DEFAULT_COOKIE_CONFIG = {
    sessionCookieName: 'sessionId',
    authDataCookieName: 'authData',
    secure: process.env.NODE_ENV === 'production',
    path: '/',
    sameSite: 'lax',
    maxAge: 60 * 60 * 24 * 7, // 7 days
};
/**
 * Set session cookie (httpOnly, secure)
 */
export function setSessionCookie(cookies, sessionId, config = {}) {
    const cfg = { ...DEFAULT_COOKIE_CONFIG, ...config };
    cookies.set(cfg.sessionCookieName, sessionId, {
        path: cfg.path,
        httpOnly: true,
        secure: cfg.secure,
        sameSite: cfg.sameSite,
        maxAge: cfg.maxAge,
    });
}
/**
 * Set auth data cookie (client-accessible)
 *
 * Contains non-sensitive session metadata for client use.
 */
export function setAuthDataCookie(cookies, session, config = {}) {
    const cfg = { ...DEFAULT_COOKIE_CONFIG, ...config };
    const authData = JSON.stringify({
        sessionId: session.id,
        user: session.user,
        expires: session.expires,
    });
    cookies.set(cfg.authDataCookieName, authData, {
        path: cfg.path,
        httpOnly: false, // Client needs access
        secure: cfg.secure,
        sameSite: 'lax',
        maxAge: cfg.maxAge,
    });
}
/**
 * Clear all session cookies
 */
export function clearSessionCookies(cookies, config = {}) {
    const cfg = { ...DEFAULT_COOKIE_CONFIG, ...config };
    cookies.delete(cfg.sessionCookieName, { path: cfg.path });
    cookies.delete(cfg.authDataCookieName, { path: cfg.path });
    // Clear legacy admin TOTP cookie
    cookies.delete('admin_totp_handle', { path: '/admin' });
}
/**
 * Get session ID from cookies
 */
export function getSessionIdFromCookies(cookies, cookieName = DEFAULT_COOKIE_CONFIG.sessionCookieName) {
    return cookies.get(cookieName);
}
/**
 * Create cookie config from session config
 */
export function sessionConfigToCookieConfig(sessionConfig) {
    return {
        sessionCookieName: sessionConfig.cookieName,
        authDataCookieName: 'authData',
        secure: sessionConfig.secureCookie,
        path: '/',
        sameSite: sessionConfig.sameSite,
        maxAge: sessionConfig.maxAge / 1000, // Convert ms to seconds
    };
}
//# sourceMappingURL=session-cookies.js.map