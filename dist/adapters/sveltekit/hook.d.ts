/**
 * SvelteKit Auth Handle
 *
 * Server hook for session management.
 *
 * @module @tinyland/auth/sveltekit
 */
import type { Handle, RequestEvent } from '@sveltejs/kit';
import type { AuthConfig, AdminUser } from '../../types/index.js';
import type { SessionManager } from '../../core/session/index.js';
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
export declare function createAuthHandle(handleConfig: AuthHandleConfig): Handle;
/**
 * Create sequence of handles
 */
export declare function sequence(...handles: Handle[]): Handle;
/**
 * Get client IP address from request
 */
export declare function getClientIp(event: RequestEvent): string;
/**
 * CSRF protection handle
 */
export declare function createCSRFHandle(config: {
    tokenHeader?: string;
    tokenCookie?: string;
    skipMethods?: string[];
    skipRoutes?: string[];
}): Handle;
//# sourceMappingURL=hook.d.ts.map