







import type { Handle, RequestEvent } from '@sveltejs/kit';
import type { Session, AuthConfig, AdminUser } from '../../types/index.js';
import type { SessionManager } from '../../core/session/index.js';
import { getSessionIdFromCookies } from './session-cookies.js';
import { hashIp, maskIp } from '../../core/security/index.js';

export interface AuthHandleConfig {
  
  sessionManager: SessionManager;
  
  config: AuthConfig;
  
  loadUser?: (userId: string) => Promise<AdminUser | null>;
  
  publicRoutes?: string[];
  
  skipRoutes?: string[];
}
















export function createAuthHandle(handleConfig: AuthHandleConfig): Handle {
  const {
    sessionManager,
    config,
    loadUser,
    skipRoutes = ['/api/health', '/favicon.ico'],
  } = handleConfig;

  return async ({ event, resolve }) => {
    
    const path = event.url.pathname;
    if (skipRoutes.some(route => path.startsWith(route))) {
      return resolve(event);
    }

    
    const sessionId = getSessionIdFromCookies(event.cookies, config.session.cookieName);

    let session: Session | null = null;
    let user: AdminUser | null = null;

    if (sessionId) {
      session = await sessionManager.getSession(sessionId);

      if (session) {
        
        if (loadUser && session.userId) {
          user = await loadUser(session.userId);
        }

        
        if (sessionManager.shouldRenewSession(session)) {
          session = await sessionManager.refreshSession(sessionId);
        }
      }
    }

    
    (event.locals as unknown as { session: Session | null }).session = session;
    (event.locals as unknown as { user: AdminUser | null }).user = user;

    
    const clientIp = getClientIp(event);
    (event.locals as unknown as { clientIp: string }).clientIp = hashIp(clientIp);
    (event.locals as unknown as { clientIpMasked: string }).clientIpMasked = maskIp(clientIp);
    (event.locals as unknown as { userAgent: string }).userAgent = event.request.headers.get('user-agent') || 'unknown';

    return resolve(event);
  };
}




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




export function getClientIp(event: RequestEvent): string {
  
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

  
  return event.getClientAddress?.() || '0.0.0.0';
}




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

    
    if (skipMethods.includes(method) || skipRoutes.some(r => path.startsWith(r))) {
      return resolve(event);
    }

    
    const headerToken = event.request.headers.get(tokenHeader);
    const cookieToken = event.cookies.get(tokenCookie);

    if (!headerToken || !cookieToken || headerToken !== cookieToken) {
      return new Response('CSRF token invalid', { status: 403 });
    }

    return resolve(event);
  };
}
