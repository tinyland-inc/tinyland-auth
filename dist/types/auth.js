/**
 * Core Authentication Types
 * Handle-based authentication with consistent camelCase schema
 *
 * @module @tinyland/auth/types
 */
/**
 * Enum-like const object for code that uses AdminRole.SUPER_ADMIN syntax
 */
export const AdminRole = {
    SUPER_ADMIN: 'super_admin',
    ADMIN: 'admin',
    EDITOR: 'editor',
    EVENT_MANAGER: 'event_manager',
    MODERATOR: 'moderator',
    CONTRIBUTOR: 'contributor',
    MEMBER: 'member',
    VIEWER: 'viewer',
};
/**
 * Role hierarchy for permission checking
 * Higher number = more permissions
 */
export const ROLE_HIERARCHY = {
    super_admin: 100,
    admin: 90,
    moderator: 70,
    editor: 60,
    event_manager: 50,
    contributor: 40,
    member: 30,
    viewer: 10,
};
// ============================================================================
// Audit Types
// ============================================================================
export var AuditEventType;
(function (AuditEventType) {
    // Authentication Events
    AuditEventType["LOGIN_SUCCESS"] = "LOGIN_SUCCESS";
    AuditEventType["LOGIN_FAILURE"] = "LOGIN_FAILURE";
    AuditEventType["LOGOUT"] = "LOGOUT";
    AuditEventType["SESSION_EXPIRED"] = "SESSION_EXPIRED";
    AuditEventType["SESSION_CREATED"] = "SESSION_CREATED";
    AuditEventType["SESSION_DESTROYED"] = "SESSION_DESTROYED";
    // TOTP Events
    AuditEventType["TOTP_ENABLED"] = "TOTP_ENABLED";
    AuditEventType["TOTP_DISABLED"] = "TOTP_DISABLED";
    AuditEventType["TOTP_SUCCESS"] = "TOTP_SUCCESS";
    AuditEventType["TOTP_FAILURE"] = "TOTP_FAILURE";
    AuditEventType["BACKUP_CODE_USED"] = "BACKUP_CODE_USED";
    AuditEventType["BACKUP_CODES_REGENERATED"] = "BACKUP_CODES_REGENERATED";
    // User Management
    AuditEventType["USER_CREATED"] = "USER_CREATED";
    AuditEventType["USER_UPDATED"] = "USER_UPDATED";
    AuditEventType["USER_DELETED"] = "USER_DELETED";
    AuditEventType["USER_LOCKED"] = "USER_LOCKED";
    AuditEventType["USER_UNLOCKED"] = "USER_UNLOCKED";
    AuditEventType["PASSWORD_CHANGED"] = "PASSWORD_CHANGED";
    AuditEventType["ROLE_CHANGED"] = "ROLE_CHANGED";
    AuditEventType["ACCOUNT_LOCKED"] = "ACCOUNT_LOCKED";
    AuditEventType["ACCOUNT_UNLOCKED"] = "ACCOUNT_UNLOCKED";
    // Invitation Events
    AuditEventType["INVITATION_CREATED"] = "INVITATION_CREATED";
    AuditEventType["INVITATION_SENT"] = "INVITATION_SENT";
    AuditEventType["INVITATION_ACCEPTED"] = "INVITATION_ACCEPTED";
    AuditEventType["INVITATION_REVOKED"] = "INVITATION_REVOKED";
    AuditEventType["INVITATION_EXPIRED"] = "INVITATION_EXPIRED";
    // Onboarding Events
    AuditEventType["ONBOARDING_STARTED"] = "ONBOARDING_STARTED";
    AuditEventType["ONBOARDING_STEP_COMPLETED"] = "ONBOARDING_STEP_COMPLETED";
    AuditEventType["ONBOARDING_COMPLETED"] = "ONBOARDING_COMPLETED";
    AuditEventType["ONBOARDING_SKIPPED"] = "ONBOARDING_SKIPPED";
    // System Events
    AuditEventType["BOOTSTRAP_INITIATED"] = "BOOTSTRAP_INITIATED";
    AuditEventType["BOOTSTRAP_COMPLETED"] = "BOOTSTRAP_COMPLETED";
    AuditEventType["SYSTEM_CONFIGURED"] = "SYSTEM_CONFIGURED";
    AuditEventType["SECURITY_SCAN"] = "SECURITY_SCAN";
})(AuditEventType || (AuditEventType = {}));
// ============================================================================
// Error Types
// ============================================================================
export var AuthErrorCode;
(function (AuthErrorCode) {
    // General Authentication
    AuthErrorCode["INVALID_CREDENTIALS"] = "INVALID_CREDENTIALS";
    AuthErrorCode["ACCOUNT_NOT_FOUND"] = "ACCOUNT_NOT_FOUND";
    AuthErrorCode["ACCOUNT_INACTIVE"] = "ACCOUNT_INACTIVE";
    AuthErrorCode["ACCOUNT_LOCKED"] = "ACCOUNT_LOCKED";
    AuthErrorCode["SESSION_EXPIRED"] = "SESSION_EXPIRED";
    AuthErrorCode["SESSION_INVALID"] = "SESSION_INVALID";
    // TOTP & 2FA
    AuthErrorCode["TOTP_REQUIRED"] = "TOTP_REQUIRED";
    AuthErrorCode["TOTP_INVALID"] = "TOTP_INVALID";
    AuthErrorCode["TOTP_EXPIRED"] = "TOTP_EXPIRED";
    AuthErrorCode["BACKUP_CODE_INVALID"] = "BACKUP_CODE_INVALID";
    AuthErrorCode["BACKUP_CODE_EXHAUSTED"] = "BACKUP_CODE_EXHAUSTED";
    // Rate Limiting & Security
    AuthErrorCode["TOO_MANY_ATTEMPTS"] = "TOO_MANY_ATTEMPTS";
    AuthErrorCode["SUSPICIOUS_ACTIVITY"] = "SUSPICIOUS_ACTIVITY";
    AuthErrorCode["IP_BLOCKED"] = "IP_BLOCKED";
    AuthErrorCode["DEVICE_NOT_RECOGNIZED"] = "DEVICE_NOT_RECOGNIZED";
    // User Management
    AuthErrorCode["HANDLE_TAKEN"] = "HANDLE_TAKEN";
    AuthErrorCode["HANDLE_INVALID"] = "HANDLE_INVALID";
    AuthErrorCode["EMAIL_TAKEN"] = "EMAIL_TAKEN";
    AuthErrorCode["PASSWORD_TOO_WEAK"] = "PASSWORD_TOO_WEAK";
    AuthErrorCode["INSUFFICIENT_PERMISSIONS"] = "INSUFFICIENT_PERMISSIONS";
    // Invitations
    AuthErrorCode["INVITATION_INVALID"] = "INVITATION_INVALID";
    AuthErrorCode["INVITATION_EXPIRED"] = "INVITATION_EXPIRED";
    AuthErrorCode["INVITATION_USED"] = "INVITATION_USED";
    AuthErrorCode["INVITATION_REVOKED"] = "INVITATION_REVOKED";
    // Onboarding
    AuthErrorCode["ONBOARDING_REQUIRED"] = "ONBOARDING_REQUIRED";
    AuthErrorCode["ONBOARDING_STEP_INCOMPLETE"] = "ONBOARDING_STEP_INCOMPLETE";
    AuthErrorCode["ONBOARDING_INVALID_STEP"] = "ONBOARDING_INVALID_STEP";
    // System
    AuthErrorCode["SYSTEM_NOT_CONFIGURED"] = "SYSTEM_NOT_CONFIGURED";
    AuthErrorCode["BOOTSTRAP_NOT_ALLOWED"] = "BOOTSTRAP_NOT_ALLOWED";
    AuthErrorCode["MAINTENANCE_MODE"] = "MAINTENANCE_MODE";
    AuthErrorCode["FEATURE_DISABLED"] = "FEATURE_DISABLED";
})(AuthErrorCode || (AuthErrorCode = {}));
// ============================================================================
// Type Guards
// ============================================================================
export function isAdminUser(obj) {
    return (typeof obj === 'object' &&
        obj !== null &&
        typeof obj.id === 'string' &&
        typeof obj.handle === 'string' &&
        typeof obj.email === 'string' &&
        typeof obj.passwordHash === 'string' &&
        typeof obj.role === 'string' &&
        typeof obj.isActive === 'boolean');
}
export function isValidAdminRole(role) {
    return Object.keys(ROLE_HIERARCHY).includes(role);
}
export function hasHigherRole(userRole, targetRole) {
    return ROLE_HIERARCHY[userRole] > ROLE_HIERARCHY[targetRole];
}
export function hasEqualOrHigherRole(userRole, targetRole) {
    return ROLE_HIERARCHY[userRole] >= ROLE_HIERARCHY[targetRole];
}
//# sourceMappingURL=auth.js.map