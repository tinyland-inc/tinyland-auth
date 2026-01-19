/**
 * SvelteKit Auth Handle
 *
 * Server hook for session management.
 *
 * @module @tinyland/auth/sveltekit
 */
import { getSessionIdFromCookies } from './session-cookies.js';
import { hashIp, maskIp } from '../../core/security/index.js';
/**
 * Create auth handle for SvelteKit
 *
 * @example
 * ```typescript
 * // src/hooks.server.ts
 * import { createAuthHandle } from '@tinyland/auth/sveltekit';
 *
 * export const handle = createAuthHandle({
 *   sessionManager,
 *   config: authConfig,
 *   loadUser: async (userId) => userService.getUser(userId),
 * });
 * ```
 */
export function createAuthHandle(handleConfig) {
    const { sessionManager, config, loadUser, skipRoutes = ['/api/health', '/favicon.ico'], } = handleConfig;
    return async ({ event, resolve }) => {
        // Skip auth for certain routes
        const path = event.url.pathname;
        if (skipRoutes.some(route => path.startsWith(route))) {
            return resolve(event);
        }
        // Get session from cookie
        const sessionId = getSessionIdFromCookies(event.cookies, config.session.cookieName);
        let session = null;
        let user = null;
        if (sessionId) {
            session = await sessionManager.getSession(sessionId);
            if (session) {
                // Load full user if loader provided
                if (loadUser && session.userId) {
                    user = await loadUser(session.userId);
                }
                // Check if session should be renewed
                if (sessionManager.shouldRenewSession(session)) {
                    session = await sessionManager.refreshSession(sessionId);
                }
            }
        }
        // Add to locals
        event.locals.session = session;
        event.locals.user = user;
        // Add request metadata to locals for logging
        const clientIp = getClientIp(event);
        event.locals.clientIp = hashIp(clientIp);
        event.locals.clientIpMasked = maskIp(clientIp);
        event.locals.userAgent = event.request.headers.get('user-agent') || 'unknown';
        return resolve(event);
    };
}
/**
 * Create sequence of handles
 */
export function sequence(...handles) {
    return async ({ event, resolve }) => {
        let resolveNext = resolve;
        for (let i = handles.length - 1; i >= 0; i--) {
            const handle = handles[i];
            const next = resolveNext;
            resolveNext = (event) => handle({ event, resolve: next });
        }
        return resolveNext(event);
    };
}
/**
 * Get client IP address from request
 */
export function getClientIp(event) {
    // Check common proxy headers
    const forwardedFor = event.request.headers.get('x-forwarded-for');
    if (forwardedFor) {
        const ips = forwardedFor.split(',').map(ip => ip.trim());
        if (ips.length > 0 && ips[0]) {
            return ips[0];
        }
    }
    const realIp = event.request.headers.get('x-real-ip');
    if (realIp) {
        return realIp;
    }
    const cfConnectingIp = event.request.headers.get('cf-connecting-ip');
    if (cfConnectingIp) {
        return cfConnectingIp;
    }
    // Fall back to connection address
    return event.getClientAddress?.() || '0.0.0.0';
}
/**
 * CSRF protection handle
 */
export function createCSRFHandle(config) {
    const { tokenHeader = 'x-csrf-token', tokenCookie = 'csrf_token', skipMethods = ['GET', 'HEAD', 'OPTIONS'], skipRoutes = [], } = config;
    return async ({ event, resolve }) => {
        const method = event.request.method;
        const path = event.url.pathname;
        // Skip for safe methods and specified routes
        if (skipMethods.includes(method) || skipRoutes.some(r => path.startsWith(r))) {
            return resolve(event);
        }
        // Validate CSRF token
        const headerToken = event.request.headers.get(tokenHeader);
        const cookieToken = event.cookies.get(tokenCookie);
        if (!headerToken || !cookieToken || headerToken !== cookieToken) {
            return new Response('CSRF token invalid', { status: 403 });
        }
        return resolve(event);
    };
}
//# sourceMappingURL=hook.js.map