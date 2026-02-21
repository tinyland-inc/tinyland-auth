/**
 * API Contract Types
 *
 * Request/Response types for REST API endpoints.
 * These define the contract between client and server.
 *
 * @module @tinyland/auth/types/api
 */

import type { AdminUser, AdminRole, AdminInvitation, AuthErrorCode } from './auth.js';

// ============================================================================
// Bootstrap Flow Types
// ============================================================================

/**
 * Request to initiate bootstrap (first super_admin creation)
 */
export interface BootstrapRequest {
  /** Unique username/handle for the admin */
  handle: string;
  /** Password (must meet policy requirements) */
  password: string;
  /** Display name shown in UI */
  displayName: string;
  /** Optional email for notifications */
  email?: string;
}

/**
 * Response from bootstrap initiation
 */
export interface BootstrapResponse {
  success: boolean;
  /** Created user (without sensitive fields) */
  user?: Omit<AdminUser, 'passwordHash'>;
  /** TOTP secret for QR code generation */
  totpSecret?: string;
  /** Data URL for QR code image */
  qrCodeUrl?: string;
  /** One-time backup recovery codes */
  backupCodes?: string[];
  error?: string;
}

/**
 * Request to verify TOTP during bootstrap
 */
export interface BootstrapVerificationRequest {
  /** Handle from bootstrap step 1 */
  handle: string;
  /** 6-digit TOTP code from authenticator */
  totpCode: string;
}

/**
 * System bootstrap status check
 */
export interface BootstrapStatus {
  /** True if no users exist and bootstrap is needed */
  needsBootstrap: boolean;
  /** True if any users exist in the system */
  hasUsers: boolean;
  /** True if system configuration is complete */
  systemConfigured: boolean;
}

// ============================================================================
// Login Flow Types
// ============================================================================

/**
 * Login request
 */
export interface LoginRequest {
  /** Handle (username) */
  handle: string;
  /** Plain text password */
  password: string;
  /** TOTP code (required if 2FA enabled) */
  totpCode?: string;
  /** Extend session duration */
  rememberMe?: boolean;
}

/**
 * Login response
 */
export interface LoginResponse {
  success: boolean;
  /** User data (without sensitive fields) */
  user?: Omit<AdminUser, 'passwordHash'>;
  /** Session token for subsequent requests */
  sessionToken?: string;
  /** Whether user needs to complete onboarding */
  needsOnboarding?: boolean;
  /** Error code for failed logins */
  error?: AuthErrorCode;
  /** Human-readable error message */
  errorMessage?: string;
  /** Additional metadata */
  metadata?: {
    /** Whether TOTP is required for this account */
    totpRequired: boolean;
    /** Whether account is locked */
    accountLocked: boolean;
    /** Remaining login attempts before lockout */
    attemptsRemaining?: number;
  };
}

/**
 * Logout request
 */
export interface LogoutRequest {
  /** Specific session to logout */
  sessionId?: string;
  /** Logout from all devices */
  logoutAll?: boolean;
}

/**
 * Logout response
 */
export interface LogoutResponse {
  success: boolean;
  /** Number of sessions terminated (if logoutAll) */
  sessionsTerminated?: number;
  error?: string;
}

// ============================================================================
// Session Management Types
// ============================================================================

/**
 * Extended session info for API responses
 */
export interface SessionInfo {
  id: string;
  userId: string;
  handle: string;
  role: AdminRole;
  displayName?: string;
  createdAt: string;
  expiresAt: string;
  lastActivity?: string;
  ipAddress?: string;
  userAgent?: string;
  isValid: boolean;
  isCurrent: boolean;
  deviceInfo?: {
    platform?: string;
    browser?: string;
    isMobile?: boolean;
  };
}

/**
 * Session refresh request
 */
export interface SessionRefreshRequest {
  sessionId: string;
}

/**
 * Session refresh response
 */
export interface SessionRefreshResponse {
  success: boolean;
  /** New session token */
  sessionToken?: string;
  /** New expiration time */
  expiresAt?: string;
  error?: string;
}

/**
 * List all sessions for current user
 */
export interface SessionListResponse {
  success: boolean;
  sessions: SessionInfo[];
  currentSessionId: string;
  error?: string;
}

/**
 * Terminate session request
 */
export interface SessionTerminateRequest {
  /** Session ID to terminate */
  sessionId: string;
}

/**
 * Terminate session response
 */
export interface SessionTerminateResponse {
  success: boolean;
  error?: string;
}

// ============================================================================
// Invitation Flow Types
// ============================================================================

/**
 * Create invitation request
 */
export interface InvitationCreateRequest {
  /** Email for reference/notification */
  email: string;
  /** Role to assign to invited user */
  role: AdminRole;
  /** Custom expiration (hours) */
  expiresInHours?: number;
  /** Personal message to include */
  message?: string;
  /** Custom setup instructions */
  customInstructions?: string;
  /** Skip sending email notification */
  skipEmailNotification?: boolean;
}

/**
 * Create invitation response
 */
export interface InvitationCreateResponse {
  success: boolean;
  invitation?: AdminInvitation;
  /** Full invitation URL */
  inviteUrl?: string;
  /** Temporary TOTP secret for setup */
  totpSecret?: string;
  /** QR code data URL */
  qrCodeUrl?: string;
  error?: string;
}

/**
 * Accept invitation request
 */
export interface InvitationAcceptRequest {
  /** Invitation token */
  token: string;
  /** Chosen handle/username */
  handle: string;
  /** Password */
  password: string;
  /** TOTP code using temporary secret */
  totpCode: string;
  /** Optional display name */
  displayName?: string;
  /** Optional email override */
  email?: string;
}

/**
 * Accept invitation response
 */
export interface InvitationAcceptResponse {
  success: boolean;
  user?: Omit<AdminUser, 'passwordHash'>;
  /** New permanent TOTP secret */
  permanentTotpSecret?: string;
  /** Backup recovery codes */
  backupCodes?: string[];
  /** Whether onboarding is required */
  needsOnboarding: boolean;
  error?: string;
}

/**
 * List invitations response
 */
export interface InvitationListResponse {
  success: boolean;
  invitations: AdminInvitation[];
  statistics: {
    total: number;
    pending: number;
    expired: number;
    used: number;
  };
  error?: string;
}

/**
 * Revoke invitation request
 */
export interface InvitationRevokeRequest {
  /** Invitation token or ID */
  tokenOrId: string;
}

/**
 * Revoke invitation response
 */
export interface InvitationRevokeResponse {
  success: boolean;
  error?: string;
}

// ============================================================================
// Onboarding Flow Types
// ============================================================================

/**
 * Onboarding status for current user
 */
export interface OnboardingStatus {
  /** Whether onboarding is required */
  needsOnboarding: boolean;
  /** Current step (0=profile, 1=security, 2=preferences) */
  currentStep: number;
  /** Steps that have been completed */
  completedSteps: number[];
  /** Whether user can skip remaining steps */
  canSkip: boolean;
  /** Estimated time to complete */
  estimatedTimeRemaining: string;
}

/**
 * Profile setup request (step 0)
 */
export interface ProfileSetupRequest {
  displayName: string;
  bio?: string;
  pronouns?: string;
  avatarUrl?: string;
}

/**
 * Security review request (step 1)
 */
export interface SecurityReviewRequest {
  /** Must confirm TOTP is enabled */
  confirmTotpEnabled: boolean;
  /** Must confirm backup codes are saved */
  downloadedBackupCodes: boolean;
  /** Must acknowledge security guidelines */
  acknowledgeSecurityGuidelines: boolean;
  /** Optional additional security settings */
  additionalSecurityMeasures?: {
    enableLoginNotifications?: boolean;
    enableLocationTracking?: boolean;
  };
}

/**
 * Preferences setup request (step 2)
 */
export interface PreferencesSetupRequest {
  timezone: string;
  locale: string;
  theme: 'light' | 'dark' | 'auto';
  emailNotifications: boolean;
  additionalPreferences?: {
    digestFrequency?: 'daily' | 'weekly' | 'monthly' | 'never';
    securityAlerts?: boolean;
    featureUpdates?: boolean;
  };
}

/**
 * Onboarding step completion response
 */
export interface OnboardingStepResponse {
  success: boolean;
  /** Next step to complete (null if done) */
  nextStep?: number | null;
  /** Whether all steps are complete */
  isComplete?: boolean;
  error?: string;
}

/**
 * Skip onboarding request
 */
export interface OnboardingSkipRequest {
  /** Acknowledge consequences of skipping */
  acknowledgeSkip: boolean;
}

// ============================================================================
// TOTP Management Types
// ============================================================================

/**
 * TOTP setup request
 */
export interface TOTPSetupRequest {
  /** Generated secret from setup flow */
  secret: string;
  /** Verification code to confirm setup */
  verificationCode: string;
}

/**
 * TOTP setup response
 */
export interface TOTPSetupResponse {
  success: boolean;
  /** Backup recovery codes */
  backupCodes?: string[];
  /** QR code data URL */
  qrCodeUrl?: string;
  error?: string;
}

/**
 * TOTP disable request
 */
export interface TOTPDisableRequest {
  /** Current password for verification */
  password: string;
  /** Current TOTP code OR backup code */
  verificationCode: string;
}

/**
 * TOTP disable response
 */
export interface TOTPDisableResponse {
  success: boolean;
  error?: string;
}

/**
 * Backup code usage request
 */
export interface BackupCodeUsageRequest {
  /** The backup code being used */
  backupCode: string;
  /** Purpose of using the code */
  purpose: 'login' | 'disable_totp' | 'account_recovery';
}

/**
 * Backup code usage response
 */
export interface BackupCodeUsageResponse {
  success: boolean;
  /** Remaining unused codes */
  codesRemaining: number;
  /** Whether new codes should be generated */
  regenerationRequired?: boolean;
  error?: string;
}

/**
 * Regenerate backup codes request
 */
export interface BackupCodesRegenerateRequest {
  /** Current password for verification */
  password: string;
  /** Current TOTP code */
  totpCode: string;
}

/**
 * Regenerate backup codes response
 */
export interface BackupCodesRegenerateResponse {
  success: boolean;
  /** New backup codes (display once) */
  backupCodes?: string[];
  error?: string;
}

// ============================================================================
// Password Management Types
// ============================================================================

/**
 * Change password request
 */
export interface PasswordChangeRequest {
  /** Current password */
  currentPassword: string;
  /** New password */
  newPassword: string;
  /** Confirm new password */
  confirmPassword: string;
  /** TOTP code for verification */
  totpCode?: string;
}

/**
 * Change password response
 */
export interface PasswordChangeResponse {
  success: boolean;
  /** Whether all other sessions were terminated */
  sessionsTerminated?: boolean;
  error?: string;
}

// ============================================================================
// User Management Types (Admin)
// ============================================================================

/**
 * List users request
 */
export interface UserListRequest {
  /** Filter by role */
  role?: AdminRole;
  /** Filter by active status */
  isActive?: boolean;
  /** Search by handle or email */
  search?: string;
  /** Pagination: page number */
  page?: number;
  /** Pagination: items per page */
  limit?: number;
}

/**
 * List users response
 */
export interface UserListResponse {
  success: boolean;
  users: Array<Omit<AdminUser, 'passwordHash'>>;
  pagination: {
    total: number;
    page: number;
    limit: number;
    totalPages: number;
  };
  error?: string;
}

/**
 * Update user request (admin)
 */
export interface UserUpdateRequest {
  userId: string;
  updates: {
    role?: AdminRole;
    isActive?: boolean;
    isLocked?: boolean;
    lockReason?: string;
    permissions?: string[];
  };
}

/**
 * Update user response
 */
export interface UserUpdateResponse {
  success: boolean;
  user?: Omit<AdminUser, 'passwordHash'>;
  error?: string;
}

/**
 * Delete user request
 */
export interface UserDeleteRequest {
  userId: string;
  /** Require confirmation */
  confirmDelete: boolean;
}

/**
 * Delete user response
 */
export interface UserDeleteResponse {
  success: boolean;
  error?: string;
}
