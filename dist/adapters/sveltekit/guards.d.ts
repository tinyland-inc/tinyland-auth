/**
 * SvelteKit Route Guards
 *
 * Protection utilities for routes requiring authentication.
 *
 * @module @tinyland/auth/sveltekit
 */
import { type RequestEvent } from '@sveltejs/kit';
import type { AdminRole, Session, AdminUser } from '../../types/auth.js';
export interface GuardOptions {
    /** Redirect URL for unauthenticated users */
    loginUrl?: string;
    /** Redirect URL after successful auth */
    returnUrl?: string;
    /** Custom error message */
    errorMessage?: string;
}
export interface GuardResult {
    /** Whether access is granted */
    allowed: boolean;
    /** Session if authenticated */
    session?: Session;
    /** User if authenticated */
    user?: AdminUser;
    /** Redirect URL if access denied */
    redirectUrl?: string;
    /** Error message if access denied */
    error?: string;
}
/**
 * Get session from locals
 */
export declare function getSessionFromLocals(locals: App.Locals): Session | null;
/**
 * Get user from locals
 */
export declare function getUserFromLocals(locals: App.Locals): AdminUser | null;
/**
 * Require authentication
 *
 * Throws redirect if not authenticated.
 */
export declare function requireAuth(locals: App.Locals, options?: GuardOptions): {
    session: Session;
    user?: AdminUser;
};
/**
 * Require specific role or higher
 *
 * Throws error if user doesn't have required role.
 */
export declare function requireRole(locals: App.Locals, requiredRole: AdminRole, options?: GuardOptions): {
    session: Session;
    user?: AdminUser;
};
/**
 * Require specific permission
 *
 * Throws error if user doesn't have required permission.
 */
export declare function requirePermission(locals: App.Locals, permission: string, options?: GuardOptions): {
    session: Session;
    user: AdminUser;
};
/**
 * Admin guard for admin panel routes
 *
 * Validates session and redirects if invalid.
 */
export declare function adminGuard(locals: App.Locals, options?: GuardOptions): {
    session: Session;
    user?: AdminUser;
};
/**
 * Check if user can manage target role
 */
export declare function canManageTargetRole(locals: App.Locals, targetRole: AdminRole): boolean;
/**
 * Guard for page load functions
 *
 * Returns guard result instead of throwing.
 */
export declare function checkAuth(locals: App.Locals, options?: {
    requiredRole?: AdminRole;
    requiredPermission?: string;
    loginUrl?: string;
}): Promise<GuardResult>;
/**
 * Protect API endpoint
 *
 * For use in +server.ts files.
 */
export declare function protectEndpoint(event: RequestEvent, options?: {
    requiredRole?: AdminRole;
    requiredPermission?: string;
}): {
    session: Session;
    user?: AdminUser;
};
//# sourceMappingURL=guards.d.ts.map