/**
 * Permission Types and Constants
 *
 * @module @tinyland/auth/types/permissions
 */
import type { AdminRole } from './auth.js';
/**
 * Permission type for validation
 */
export type AdminPermission = 'admin.access' | 'admin.users.view' | 'admin.users.manage' | 'admin.users.delete' | 'admin.content.view' | 'admin.content.manage' | 'admin.content.moderate' | 'admin.events.view' | 'admin.events.manage' | 'admin.analytics.view' | 'admin.analytics.export' | 'admin.settings.view' | 'admin.settings.manage' | 'admin.security.view' | 'admin.security.manage' | 'admin.logs.view' | 'admin.logs.export';
/**
 * Permission definitions
 */
export declare const PERMISSIONS: {
    readonly ADMIN_ACCESS: "admin.access";
    readonly ADMIN_USERS_VIEW: "admin.users.view";
    readonly ADMIN_USERS_MANAGE: "admin.users.manage";
    readonly ADMIN_USERS_DELETE: "admin.users.delete";
    readonly ADMIN_CONTENT_VIEW: "admin.content.view";
    readonly ADMIN_CONTENT_MANAGE: "admin.content.manage";
    readonly ADMIN_CONTENT_MODERATE: "admin.content.moderate";
    readonly ADMIN_EVENTS_VIEW: "admin.events.view";
    readonly ADMIN_EVENTS_MANAGE: "admin.events.manage";
    readonly ADMIN_ANALYTICS_VIEW: "admin.analytics.view";
    readonly ADMIN_ANALYTICS_EXPORT: "admin.analytics.export";
    readonly ADMIN_SETTINGS_VIEW: "admin.settings.view";
    readonly ADMIN_SETTINGS_MANAGE: "admin.settings.manage";
    readonly ADMIN_SECURITY_VIEW: "admin.security.view";
    readonly ADMIN_SECURITY_MANAGE: "admin.security.manage";
    readonly ADMIN_LOGS_VIEW: "admin.logs.view";
    readonly ADMIN_LOGS_EXPORT: "admin.logs.export";
};
/**
 * Role-based permission presets
 */
export declare const ROLE_PERMISSIONS: Record<AdminRole, string[]>;
/**
 * Content visibility levels
 */
export type ContentVisibility = 'public' | 'members' | 'admin' | 'private';
/**
 * Validation rules for user input
 */
export declare const VALIDATION_RULES: {
    readonly username: {
        readonly pattern: RegExp;
        readonly minLength: 3;
        readonly maxLength: 20;
        readonly message: "Username must be 3-20 characters, alphanumeric with _ or -";
    };
    readonly handle: {
        readonly pattern: RegExp;
        readonly minLength: 3;
        readonly maxLength: 20;
        readonly message: "Handle must be 3-20 characters, alphanumeric with _ or -";
    };
    readonly password: {
        readonly minLength: 12;
        readonly requireUppercase: true;
        readonly requireLowercase: true;
        readonly requireNumber: true;
        readonly requireSpecial: true;
        readonly message: "Password must be at least 12 characters with uppercase, lowercase, number, and special character";
    };
};
//# sourceMappingURL=permissions.d.ts.map