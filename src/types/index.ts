/**
 * Type Definitions Export
 *
 * @module @tinyland/auth/types
 */

// Auth types - AdminRole is both a type and const object, export as value
export {
  AdminRole,
  ROLE_HIERARCHY,
  AuditEventType,
  AuthErrorCode,
  isAdminUser,
  isValidAdminRole,
  hasHigherRole,
  hasEqualOrHigherRole,
} from './auth.js';

// Auth type-only exports
export type {
  AdminUser,
  DeviceType,
  Session,
  SessionUser,
  SessionMetadata,
  TOTPSecret,
  EncryptedTOTPSecret,
  EncryptedData,
  BackupCode,
  BackupCodeSet,
  EncryptedBackupCode,
  AdminInvitation,
  AuditSeverity,
  AuditEvent,
  AuthError,
} from './auth.js';

// Config value exports
export {
  DEFAULT_AUTH_CONFIG,
  createAuthConfig,
} from './config.js';

// Config type-only exports
export type {
  AuthConfig,
  TOTPConfig,
  SessionConfig,
  PasswordConfig,
  RateLimitConfig,
  InvitationConfig,
  BackupCodesConfig,
  SecurityConfig,
} from './config.js';

// Permission value exports
export {
  PERMISSIONS,
  ROLE_PERMISSIONS,
  VALIDATION_RULES,
} from './permissions.js';

// Permission type-only exports
export type {
  AdminPermission,
  ContentVisibility,
} from './permissions.js';

// API contract types
export type {
  // Bootstrap
  BootstrapRequest,
  BootstrapResponse,
  BootstrapVerificationRequest,
  BootstrapStatus,
  // Login
  LoginRequest,
  LoginResponse,
  LogoutRequest,
  LogoutResponse,
  // Session
  SessionInfo,
  SessionRefreshRequest,
  SessionRefreshResponse,
  SessionListResponse,
  SessionTerminateRequest,
  SessionTerminateResponse,
  // Invitation
  InvitationCreateRequest,
  InvitationCreateResponse,
  InvitationAcceptRequest,
  InvitationAcceptResponse,
  InvitationListResponse,
  InvitationRevokeRequest,
  InvitationRevokeResponse,
  // Onboarding
  OnboardingStatus,
  ProfileSetupRequest,
  SecurityReviewRequest,
  PreferencesSetupRequest,
  OnboardingStepResponse,
  OnboardingSkipRequest,
  // TOTP
  TOTPSetupRequest,
  TOTPSetupResponse,
  TOTPDisableRequest,
  TOTPDisableResponse,
  BackupCodeUsageRequest,
  BackupCodeUsageResponse,
  BackupCodesRegenerateRequest,
  BackupCodesRegenerateResponse,
  // Password
  PasswordChangeRequest,
  PasswordChangeResponse,
  // User Management
  UserListRequest,
  UserListResponse,
  UserUpdateRequest,
  UserUpdateResponse,
  UserDeleteRequest,
  UserDeleteResponse,
} from './api.js';
