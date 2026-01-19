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

export const DEFAULT_COOKIE_CONFIG: CookieConfig = {
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
export function setSessionCookie(
  cookies: Cookies,
  sessionId: string,
  config: Partial<CookieConfig> = {}
): void {
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
export function setAuthDataCookie(
  cookies: Cookies,
  session: Session,
  config: Partial<CookieConfig> = {}
): void {
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
export function clearSessionCookies(
  cookies: Cookies,
  config: Partial<CookieConfig> = {}
): void {
  const cfg = { ...DEFAULT_COOKIE_CONFIG, ...config };

  cookies.delete(cfg.sessionCookieName, { path: cfg.path });
  cookies.delete(cfg.authDataCookieName, { path: cfg.path });

  // Clear legacy admin TOTP cookie
  cookies.delete('admin_totp_handle', { path: '/admin' });
}

/**
 * Get session ID from cookies
 */
export function getSessionIdFromCookies(
  cookies: Cookies,
  cookieName: string = DEFAULT_COOKIE_CONFIG.sessionCookieName
): string | undefined {
  return cookies.get(cookieName);
}

/**
 * Create cookie config from session config
 */
export function sessionConfigToCookieConfig(sessionConfig: SessionConfig): CookieConfig {
  return {
    sessionCookieName: sessionConfig.cookieName,
    authDataCookieName: 'authData',
    secure: sessionConfig.secureCookie,
    path: '/',
    sameSite: sessionConfig.sameSite,
    maxAge: sessionConfig.maxAge / 1000, // Convert ms to seconds
  };
}
