/**
 * Permission Management System
 *
 * Centralized permission management with 40+ pure functions for RBAC.
 * All functions are pure (no I/O) and can be used in any context.
 *
 * @module @tinyland/auth/core/permissions
 */
import type { AdminRole, AdminUser } from '../../types/auth.js';
import { type ContentVisibility } from '../../types/permissions.js';
/**
 * Get default permissions for a given role
 */
export declare function getRolePermissions(role: AdminRole | string): string[];
/**
 * Check if a user has a specific permission
 */
export declare function hasPermission(user: AdminUser, permission: string): boolean;
/**
 * Check if a user has any of the specified permissions
 */
export declare function hasAnyPermission(user: AdminUser, permissions: string[]): boolean;
/**
 * Check if a user has all of the specified permissions
 */
export declare function hasAllPermissions(user: AdminUser, permissions: string[]): boolean;
/**
 * Throws an error if user doesn't have the required permission
 */
export declare function requirePermission(user: AdminUser, permission: string): void;
/**
 * Throws an error if user doesn't have any of the required permissions
 */
export declare function requireAnyPermission(user: AdminUser, permissions: string[]): void;
/**
 * Throws an error if user doesn't have all of the required permissions
 */
export declare function requireAllPermissions(user: AdminUser, permissions: string[]): void;
/**
 * Get all permissions for a user (combines role and explicit permissions)
 */
export declare function getUserPermissions(user: AdminUser): string[];
/**
 * Check if a role can manage another role (role hierarchy check)
 */
export declare function canManageRole(actorRole: AdminRole | string, targetRole: AdminRole | string): boolean;
/**
 * Validate if a permission string is valid
 */
export declare function isValidPermission(permission: string): boolean;
/**
 * Get permission display name (human-readable)
 */
export declare function getPermissionDisplayName(permission: string): string;
export declare function canViewPosts(role: AdminRole | string): boolean;
export declare function canCreatePosts(role: AdminRole | string): boolean;
export declare function canEditPosts(role: AdminRole | string): boolean;
export declare function canDeletePosts(role: AdminRole | string): boolean;
export declare function canViewEvents(role: AdminRole | string): boolean;
export declare function canCreateEvents(role: AdminRole | string): boolean;
export declare function canEditEvents(role: AdminRole | string): boolean;
export declare function canDeleteEvents(role: AdminRole | string): boolean;
export declare function canViewProfiles(role: AdminRole | string): boolean;
export declare function canCreateProfiles(role: AdminRole | string): boolean;
export declare function canEditOwnProfile(role: AdminRole | string): boolean;
export declare function canEditAnyProfile(role: AdminRole | string): boolean;
export declare function canDeleteProfiles(role: AdminRole | string): boolean;
export declare function canViewUsers(role: AdminRole | string): boolean;
export declare function canManageUsers(role: AdminRole | string): boolean;
export declare function canViewVideos(role: AdminRole | string): boolean;
export declare function canCreateVideos(role: AdminRole | string): boolean;
export declare function canEditVideos(role: AdminRole | string): boolean;
export declare function canDeleteVideos(role: AdminRole | string): boolean;
export declare function canCreatePublicContent(role: AdminRole | string): boolean;
export declare function canCreateMemberOnlyContent(role: AdminRole | string): boolean;
export declare function canFeatureProfile(role: AdminRole | string): boolean;
export declare function canEditOwnContent(role: AdminRole | string): boolean;
export declare function canDeleteOwnContent(role: AdminRole | string): boolean;
export declare function canEditContent(role: AdminRole | string): boolean;
export declare function canDeleteContent(role: AdminRole | string): boolean;
export declare function isMemberRole(role: AdminRole | string): boolean;
export declare function canViewMemberOnlyContent(role: AdminRole | string): boolean;
export declare function getAllowedVisibilityOptions(role: AdminRole | string): string[];
/**
 * Check if a user can view content with a given visibility level
 */
export declare function canViewContent(visibility: ContentVisibility | string | undefined, userRole: AdminRole | string | null | undefined, authorId?: string | null, userId?: string | null): boolean;
/**
 * Filter an array of content items by visibility
 */
export declare function filterContentByVisibility<T extends {
    visibility?: string;
    authorId?: string;
}>(items: T[], userRole: AdminRole | string | null | undefined, userId?: string | null): T[];
export { PERMISSIONS, ROLE_PERMISSIONS } from '../../types/permissions.js';
//# sourceMappingURL=index.d.ts.map