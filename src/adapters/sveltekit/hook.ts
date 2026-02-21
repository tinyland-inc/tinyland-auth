/**
 * SvelteKit Auth Handle
 *
 * Server hook for session management.
 *
 * @module @tinyland/auth/sveltekit
 */

import type { Handle, RequestEvent } from '@sveltejs/kit';
import type { Session, AuthConfig, AdminUser } from '../../types/index.js';
import type { SessionManager } from '../../core/session/index.js';
import { getSessionIdFromCookies } from './session-cookies.js';
import { hashIp, maskIp } from '../../core/security/index.js';

export interface AuthHandleConfig {
  /** Session manager instance */
  sessionManager: SessionManager;
  /** Auth configuration */
  config: AuthConfig;
  /** Function to load user by ID */
  loadUser?: (userId: string) => Promise<AdminUser | null>;
  /** Public routes that don't require auth */
  publicRoutes?: string[];
  /** Routes to skip auth check entirely */
  skipRoutes?: string[];
}

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
export function createAuthHandle(handleConfig: AuthHandleConfig): Handle {
  const {
    sessionManager,
    config,
    loadUser,
    skipRoutes = ['/api/health', '/favicon.ico'],
  } = handleConfig;

  return async ({ event, resolve }) => {
    // Skip auth for certain routes
    const path = event.url.pathname;
    if (skipRoutes.some(route => path.startsWith(route))) {
      return resolve(event);
    }

    // Get session from cookie
    const sessionId = getSessionIdFromCookies(event.cookies, config.session.cookieName);

    let session: Session | null = null;
    let user: AdminUser | null = null;

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
    (event.locals as unknown as { session: Session | null }).session = session;
    (event.locals as unknown as { user: AdminUser | null }).user = user;

    // Add request metadata to locals for logging
    const clientIp = getClientIp(event);
    (event.locals as unknown as { clientIp: string }).clientIp = hashIp(clientIp);
    (event.locals as unknown as { clientIpMasked: string }).clientIpMasked = maskIp(clientIp);
    (event.locals as unknown as { userAgent: string }).userAgent = event.request.headers.get('user-agent') || 'unknown';

    return resolve(event);
  };
}

/**
 * Create sequence of handles
 */
export function sequence(...handles: Handle[]): Handle {
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
export function getClientIp(event: RequestEvent): string {
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
export function createCSRFHandle(config: {
  tokenHeader?: string;
  tokenCookie?: string;
  skipMethods?: string[];
  skipRoutes?: string[];
}): Handle {
  const {
    tokenHeader = 'x-csrf-token',
    tokenCookie = 'csrf_token',
    skipMethods = ['GET', 'HEAD', 'OPTIONS'],
    skipRoutes = [],
  } = config;

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
