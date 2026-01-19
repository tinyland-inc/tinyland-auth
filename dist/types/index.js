/**
 * Type Definitions Export
 *
 * @module @tinyland/auth/types
 */
// Auth types - AdminRole is both a type and const object, export as value
export { AdminRole, ROLE_HIERARCHY, AuditEventType, AuthErrorCode, isAdminUser, isValidAdminRole, hasHigherRole, hasEqualOrHigherRole, } from './auth.js';
// Config value exports
export { DEFAULT_AUTH_CONFIG, createAuthConfig, } from './config.js';
// Permission value exports
export { PERMISSIONS, ROLE_PERMISSIONS, VALIDATION_RULES, } from './permissions.js';
//# sourceMappingURL=index.js.map