







import { error, redirect, type RequestEvent } from '@sveltejs/kit';
import type { AdminRole, Session, AdminUser } from '../../types/auth.js';
import { hasEqualOrHigherRole } from '../../types/auth.js';
import { hasPermission, canManageRole } from '../../core/permissions/index.js';

export interface GuardOptions {
  
  loginUrl?: string;
  
  returnUrl?: string;
  
  errorMessage?: string;
}

export interface GuardResult {
  
  allowed: boolean;
  
  session?: Session;
  
  user?: AdminUser;
  
  redirectUrl?: string;
  
  error?: string;
}




export function getSessionFromLocals(locals: App.Locals): Session | null {
  return (locals as unknown as { session?: Session }).session || null;
}




export function getUserFromLocals(locals: App.Locals): AdminUser | null {
  return (locals as unknown as { user?: AdminUser }).user || null;
}






export function requireAuth(
  locals: App.Locals,
  options: GuardOptions = {}
): { session: Session; user?: AdminUser } {
  const session = getSessionFromLocals(locals);

  if (!session) {
    const loginUrl = options.loginUrl || '/admin/login';
    const returnUrl = options.returnUrl ? `?returnUrl=${encodeURIComponent(options.returnUrl)}` : '';
    throw redirect(303, `${loginUrl}${returnUrl}`);
  }

  const user = getUserFromLocals(locals);
  return { session, user: user || undefined };
}






export function requireRole(
  locals: App.Locals,
  requiredRole: AdminRole,
  options: GuardOptions = {}
): { session: Session; user?: AdminUser } {
  const { session, user } = requireAuth(locals, options);

  const userRole = session.user?.role as AdminRole | undefined;
  if (!userRole || !hasEqualOrHigherRole(userRole, requiredRole)) {
    throw error(403, options.errorMessage || `Role ${requiredRole} or higher required`);
  }

  return { session, user };
}






export function requirePermission(
  locals: App.Locals,
  permission: string,
  options: GuardOptions = {}
): { session: Session; user: AdminUser } {
  const { session } = requireAuth(locals, options);
  const user = getUserFromLocals(locals);

  if (!user || !hasPermission(user, permission)) {
    throw error(403, options.errorMessage || `Permission ${permission} required`);
  }

  return { session, user };
}






export function adminGuard(
  locals: App.Locals,
  options: GuardOptions = {}
): { session: Session; user?: AdminUser } {
  return requireAuth(locals, {
    loginUrl: '/admin/login',
    ...options,
  });
}




export function canManageTargetRole(
  locals: App.Locals,
  targetRole: AdminRole
): boolean {
  const session = getSessionFromLocals(locals);
  if (!session?.user?.role) return false;

  return canManageRole(session.user.role as AdminRole, targetRole);
}






export async function checkAuth(
  locals: App.Locals,
  options: {
    requiredRole?: AdminRole;
    requiredPermission?: string;
    loginUrl?: string;
  } = {}
): Promise<GuardResult> {
  const session = getSessionFromLocals(locals);

  if (!session) {
    return {
      allowed: false,
      redirectUrl: options.loginUrl || '/admin/login',
      error: 'Authentication required',
    };
  }

  
  if (options.requiredRole) {
    const userRole = session.user?.role as AdminRole | undefined;
    if (!userRole || !hasEqualOrHigherRole(userRole, options.requiredRole)) {
      return {
        allowed: false,
        session,
        error: `Role ${options.requiredRole} or higher required`,
      };
    }
  }

  
  if (options.requiredPermission) {
    const user = getUserFromLocals(locals);
    if (!user || !hasPermission(user, options.requiredPermission)) {
      return {
        allowed: false,
        session,
        error: `Permission ${options.requiredPermission} required`,
      };
    }
  }

  return {
    allowed: true,
    session,
    user: getUserFromLocals(locals) || undefined,
  };
}






export function protectEndpoint(
  event: RequestEvent,
  options: {
    requiredRole?: AdminRole;
    requiredPermission?: string;
  } = {}
): { session: Session; user?: AdminUser } {
  const session = getSessionFromLocals(event.locals);

  if (!session) {
    throw error(401, 'Authentication required');
  }

  if (options.requiredRole) {
    const userRole = session.user?.role as AdminRole | undefined;
    if (!userRole || !hasEqualOrHigherRole(userRole, options.requiredRole)) {
      throw error(403, `Role ${options.requiredRole} or higher required`);
    }
  }

  if (options.requiredPermission) {
    const user = getUserFromLocals(event.locals);
    if (!user || !hasPermission(user, options.requiredPermission)) {
      throw error(403, `Permission ${options.requiredPermission} required`);
    }
  }

  return { session, user: getUserFromLocals(event.locals) || undefined };
}
