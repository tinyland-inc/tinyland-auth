/**
 * @tinyland/auth - Production-grade authentication system
 *
 * Features:
 * - TOTP with AES-256-GCM encryption
 * - 8-tier role-based access control (RBAC)
 * - Pluggable storage backends
 * - Session management with observability
 * - Backup code recovery
 * - Invitation flow
 * - Audit logging
 *
 * @example
 * ```typescript
 * import {
 *   createAuthConfig,
 *   createSessionManager,
 *   hasPermission,
 *   AdminRole,
 * } from '@tinyland/auth';
 *
 * // For SvelteKit:
 * import { createAuthHandle, adminGuard } from '@tinyland/auth/sveltekit';
 * ```
 *
 * @module @tinyland/auth
 */
export { AdminRole, ROLE_HIERARCHY, AuditEventType, AuthErrorCode, isAdminUser, isValidAdminRole, hasHigherRole, hasEqualOrHigherRole, DEFAULT_AUTH_CONFIG, createAuthConfig, PERMISSIONS, ROLE_PERMISSIONS, VALIDATION_RULES, } from './types/index.js';
export type { AdminUser, DeviceType, Session, SessionUser, SessionMetadata, TOTPSecret, EncryptedTOTPSecret, EncryptedData, BackupCode, BackupCodeSet, EncryptedBackupCode, AdminInvitation, AuditSeverity, AuditEvent, AuthError, AuthConfig, TOTPConfig, SessionConfig, PasswordConfig, RateLimitConfig, InvitationConfig, BackupCodesConfig, SecurityConfig, AdminPermission, ContentVisibility, BootstrapRequest, BootstrapResponse, BootstrapVerificationRequest, BootstrapStatus, LoginRequest, LoginResponse, LogoutRequest, LogoutResponse, SessionInfo, SessionRefreshRequest, SessionRefreshResponse, SessionListResponse, SessionTerminateRequest, SessionTerminateResponse, InvitationCreateRequest, InvitationCreateResponse, InvitationAcceptRequest, InvitationAcceptResponse, InvitationListResponse, InvitationRevokeRequest, InvitationRevokeResponse, OnboardingStatus, ProfileSetupRequest, SecurityReviewRequest, PreferencesSetupRequest, OnboardingStepResponse, OnboardingSkipRequest, TOTPSetupRequest, TOTPSetupResponse, TOTPDisableRequest, TOTPDisableResponse, BackupCodeUsageRequest, BackupCodeUsageResponse, BackupCodesRegenerateRequest, BackupCodesRegenerateResponse, PasswordChangeRequest, PasswordChangeResponse, UserListRequest, UserListResponse, UserUpdateRequest, UserUpdateResponse, UserDeleteRequest, UserDeleteResponse, } from './types/index.js';
export { getRolePermissions, hasPermission, hasAnyPermission, hasAllPermissions, requirePermission, requireAnyPermission, requireAllPermissions, getUserPermissions, canManageRole, isValidPermission, getPermissionDisplayName, canViewPosts, canCreatePosts, canEditPosts, canDeletePosts, canViewEvents, canCreateEvents, canEditEvents, canDeleteEvents, canViewProfiles, canCreateProfiles, canEditOwnProfile, canEditAnyProfile, canDeleteProfiles, canViewUsers, canManageUsers, canViewVideos, canCreateVideos, canEditVideos, canDeleteVideos, canCreatePublicContent, canCreateMemberOnlyContent, canFeatureProfile, canEditOwnContent, canDeleteOwnContent, canEditContent, canDeleteContent, isMemberRole, canViewMemberOnlyContent, getAllowedVisibilityOptions, canViewContent, filterContentByVisibility, } from './core/permissions/index.js';
export { constantTimeCompare, timingSafeVerify, timingSafeQuery, timingSafeError, hashIp, maskIp, validatePassword, type PasswordValidationResult, type PasswordPolicy, TimingMetrics, timingMetrics, hashPassword, verifyPassword, needsRehash, getHashRounds, generateSecurePassword, type PasswordHashConfig, } from './core/security/index.js';
export { TOTPService, createTOTPService, type TOTPServiceConfig, } from './core/totp/index.js';
export { generateBackupCodes, hashBackupCode, createBackupCodeSet, verifyBackupCode, getRemainingCodesCount, hasUnusedCodes, isValidCodeFormat, formatCodesForDisplay, shouldRegenerateCodes, DEFAULT_BACKUP_CODES_CONFIG, } from './core/backup-codes/index.js';
export { SessionManager, createSessionManager, classifyDevice, extractBrowserInfo, type SessionManagerConfig, } from './core/session/index.js';
export { type IStorageAdapter, type AuditEventFilters, type StorageAdapterConfig, MemoryStorageAdapter, FileStorageAdapter, createFileStorageAdapter, type FileStorageConfig, } from './storage/index.js';
export { AuditLogger, createAuditLogger, getSeverityForEventType, type AuditLoggerConfig, } from './modules/audit/index.js';
export { InvitationService, createInvitationService, type InvitationServiceConfig, type CreateInvitationOptions, type CreateInvitationResult, } from './modules/invitation/index.js';
export { BootstrapService, createBootstrapService, type BootstrapServiceConfig, type BootstrapState, } from './modules/bootstrap/index.js';
//# sourceMappingURL=index.d.ts.map