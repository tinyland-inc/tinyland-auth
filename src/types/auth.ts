/**
 * Core Authentication Types
 * Handle-based authentication with consistent camelCase schema
 *
 * @module @tinyland/auth/types
 */

// ============================================================================
// Role Types
// ============================================================================

export type AdminRole =
  | 'super_admin'
  | 'admin'
  | 'moderator'
  | 'editor'
  | 'event_manager'
  | 'contributor'
  | 'member'
  | 'viewer';

/**
 * Enum-like const object for code that uses AdminRole.SUPER_ADMIN syntax
 */
export const AdminRole = {
  SUPER_ADMIN: 'super_admin' as const,
  ADMIN: 'admin' as const,
  EDITOR: 'editor' as const,
  EVENT_MANAGER: 'event_manager' as const,
  MODERATOR: 'moderator' as const,
  CONTRIBUTOR: 'contributor' as const,
  MEMBER: 'member' as const,
  VIEWER: 'viewer' as const,
};

/**
 * Role hierarchy for permission checking
 * Higher number = more permissions
 */
export const ROLE_HIERARCHY: Record<AdminRole, number> = {
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
// User Types
// ============================================================================

export interface AdminUser {
  // Core Identity
  id: string;
  handle: string;
  email: string;
  displayName?: string;

  // Authentication
  passwordHash: string;
  totpEnabled: boolean;
  totpSecretId?: string;

  // Role & Permissions
  role: AdminRole;
  permissions?: string[];

  // Status Management
  isActive: boolean;
  isLocked?: boolean;
  lockReason?: string;
  lockedAt?: string;

  // Onboarding State
  needsOnboarding: boolean;
  onboardingStep: number;
  firstLogin?: boolean;

  // Timestamps
  createdAt: string;
  updatedAt: string;
  lastLoginAt?: string;
  passwordChangedAt?: string;

  // Profile Data
  bio?: string;
  avatarUrl?: string;
  pronouns?: string;

  // User Preferences
  timezone?: string;
  locale?: string;
  theme?: 'light' | 'dark' | 'auto';
  emailNotifications?: boolean;

  // Security Metadata
  loginAttempts?: number;
  lastFailedLoginAt?: string;
  ipAddress?: string;
  userAgent?: string;
}

// ============================================================================
// Session Types
// ============================================================================

export type DeviceType = 'mobile' | 'tablet' | 'desktop' | 'unknown';

export interface Session {
  id: string;
  userId: string;
  expires: string;
  expiresAt: string;
  createdAt: string;
  user?: SessionUser;

  // Observability Context
  clientIp: string;
  clientIpMasked?: string;
  userAgent: string;
  deviceType?: DeviceType;
  browserFingerprint?: string;
  geoLocation?: {
    country: string;
    city?: string;
  };

  // Temporary data for onboarding flow
  tempTotpSecret?: string;
  tempTotpExpiresAt?: string;
}

export interface SessionUser {
  id: string;
  username: string;
  name: string;
  role: string;
  needsOnboarding?: boolean;
  onboardingStep?: number;
}

export interface SessionMetadata {
  clientIp: string;
  clientIpMasked?: string;
  userAgent: string;
  deviceType?: DeviceType;
  browserFingerprint?: string;
  geoLocation?: {
    country: string;
    city?: string;
  };
}

// ============================================================================
// TOTP Types
// ============================================================================

export interface TOTPSecret {
  handle: string;
  email: string;
  secret: string;
  qrCodeUrl?: string;
  createdAt: Date;
  lastUsed?: Date;
}

export interface EncryptedTOTPSecret {
  userId: string;
  handle: string;
  encryptedSecret: string;
  iv: string;
  authTag: string;
  salt: string;
  createdAt: string;
  lastUsedAt?: string;
  backupCodesGenerated: boolean;
  version: number;
}

export interface EncryptedData {
  encrypted: string;
  salt: string;
  iv: string;
  tag: string;
}

// ============================================================================
// Backup Code Types
// ============================================================================

export interface BackupCode {
  id: string;
  userId: string;
  codeHash: string;
  used: boolean;
  usedAt?: string;
  createdAt: string;
}

export interface BackupCodeSet {
  userId: string;
  codes: EncryptedBackupCode[];
  generatedAt: string;
  lastUsedAt?: string;
}

export interface EncryptedBackupCode {
  id: string;
  hash: string;
  used: boolean;
  usedAt?: string;
}

// ============================================================================
// Invitation Types
// ============================================================================

export interface AdminInvitation {
  id: string;
  token: string;
  email: string;
  role: AdminRole;
  createdBy: string;
  createdAt: string;
  expiresAt: string;
  usedAt?: string;
  usedBy?: string;
  temporaryTotpSecret?: string;
  isActive: boolean;
  metadata?: {
    inviterHandle: string;
    inviterDisplayName?: string;
    message?: string;
    customInstructions?: string;
  };
}

// ============================================================================
// Audit Types
// ============================================================================

export enum AuditEventType {
  // Authentication Events
  LOGIN_SUCCESS = 'LOGIN_SUCCESS',
  LOGIN_FAILURE = 'LOGIN_FAILURE',
  LOGOUT = 'LOGOUT',
  SESSION_EXPIRED = 'SESSION_EXPIRED',
  SESSION_CREATED = 'SESSION_CREATED',
  SESSION_DESTROYED = 'SESSION_DESTROYED',

  // TOTP Events
  TOTP_ENABLED = 'TOTP_ENABLED',
  TOTP_DISABLED = 'TOTP_DISABLED',
  TOTP_SUCCESS = 'TOTP_SUCCESS',
  TOTP_FAILURE = 'TOTP_FAILURE',
  BACKUP_CODE_USED = 'BACKUP_CODE_USED',
  BACKUP_CODES_REGENERATED = 'BACKUP_CODES_REGENERATED',

  // User Management
  USER_CREATED = 'USER_CREATED',
  USER_UPDATED = 'USER_UPDATED',
  USER_DELETED = 'USER_DELETED',
  USER_LOCKED = 'USER_LOCKED',
  USER_UNLOCKED = 'USER_UNLOCKED',
  PASSWORD_CHANGED = 'PASSWORD_CHANGED',
  ROLE_CHANGED = 'ROLE_CHANGED',
  ACCOUNT_LOCKED = 'ACCOUNT_LOCKED',
  ACCOUNT_UNLOCKED = 'ACCOUNT_UNLOCKED',

  // Invitation Events
  INVITATION_CREATED = 'INVITATION_CREATED',
  INVITATION_SENT = 'INVITATION_SENT',
  INVITATION_ACCEPTED = 'INVITATION_ACCEPTED',
  INVITATION_REVOKED = 'INVITATION_REVOKED',
  INVITATION_EXPIRED = 'INVITATION_EXPIRED',

  // Onboarding Events
  ONBOARDING_STARTED = 'ONBOARDING_STARTED',
  ONBOARDING_STEP_COMPLETED = 'ONBOARDING_STEP_COMPLETED',
  ONBOARDING_COMPLETED = 'ONBOARDING_COMPLETED',
  ONBOARDING_SKIPPED = 'ONBOARDING_SKIPPED',

  // System Events
  BOOTSTRAP_INITIATED = 'BOOTSTRAP_INITIATED',
  BOOTSTRAP_COMPLETED = 'BOOTSTRAP_COMPLETED',
  SYSTEM_CONFIGURED = 'SYSTEM_CONFIGURED',
  SECURITY_SCAN = 'SECURITY_SCAN',
}

export type AuditSeverity = 'info' | 'warning' | 'error' | 'critical';

export interface AuditEvent {
  id: string;
  timestamp: string;
  type: AuditEventType;
  userId?: string;
  targetUserId?: string;
  handle?: string;
  ipAddress?: string;
  userAgent?: string;
  details: Record<string, unknown>;
  severity: AuditSeverity;
  source: 'system' | 'user' | 'admin';
}

// ============================================================================
// Error Types
// ============================================================================

export enum AuthErrorCode {
  // General Authentication
  INVALID_CREDENTIALS = 'INVALID_CREDENTIALS',
  ACCOUNT_NOT_FOUND = 'ACCOUNT_NOT_FOUND',
  ACCOUNT_INACTIVE = 'ACCOUNT_INACTIVE',
  ACCOUNT_LOCKED = 'ACCOUNT_LOCKED',
  SESSION_EXPIRED = 'SESSION_EXPIRED',
  SESSION_INVALID = 'SESSION_INVALID',

  // TOTP & 2FA
  TOTP_REQUIRED = 'TOTP_REQUIRED',
  TOTP_INVALID = 'TOTP_INVALID',
  TOTP_EXPIRED = 'TOTP_EXPIRED',
  BACKUP_CODE_INVALID = 'BACKUP_CODE_INVALID',
  BACKUP_CODE_EXHAUSTED = 'BACKUP_CODE_EXHAUSTED',

  // Rate Limiting & Security
  TOO_MANY_ATTEMPTS = 'TOO_MANY_ATTEMPTS',
  SUSPICIOUS_ACTIVITY = 'SUSPICIOUS_ACTIVITY',
  IP_BLOCKED = 'IP_BLOCKED',
  DEVICE_NOT_RECOGNIZED = 'DEVICE_NOT_RECOGNIZED',

  // User Management
  HANDLE_TAKEN = 'HANDLE_TAKEN',
  HANDLE_INVALID = 'HANDLE_INVALID',
  EMAIL_TAKEN = 'EMAIL_TAKEN',
  PASSWORD_TOO_WEAK = 'PASSWORD_TOO_WEAK',
  INSUFFICIENT_PERMISSIONS = 'INSUFFICIENT_PERMISSIONS',

  // Invitations
  INVITATION_INVALID = 'INVITATION_INVALID',
  INVITATION_EXPIRED = 'INVITATION_EXPIRED',
  INVITATION_USED = 'INVITATION_USED',
  INVITATION_REVOKED = 'INVITATION_REVOKED',

  // Onboarding
  ONBOARDING_REQUIRED = 'ONBOARDING_REQUIRED',
  ONBOARDING_STEP_INCOMPLETE = 'ONBOARDING_STEP_INCOMPLETE',
  ONBOARDING_INVALID_STEP = 'ONBOARDING_INVALID_STEP',

  // System
  SYSTEM_NOT_CONFIGURED = 'SYSTEM_NOT_CONFIGURED',
  BOOTSTRAP_NOT_ALLOWED = 'BOOTSTRAP_NOT_ALLOWED',
  MAINTENANCE_MODE = 'MAINTENANCE_MODE',
  FEATURE_DISABLED = 'FEATURE_DISABLED',
}

export interface AuthError {
  code: AuthErrorCode;
  message: string;
  details?: Record<string, unknown>;
  timestamp: string;
  requestId?: string;
}

// ============================================================================
// Type Guards
// ============================================================================

export function isAdminUser(obj: unknown): obj is AdminUser {
  return (
    typeof obj === 'object' &&
    obj !== null &&
    typeof (obj as AdminUser).id === 'string' &&
    typeof (obj as AdminUser).handle === 'string' &&
    typeof (obj as AdminUser).email === 'string' &&
    typeof (obj as AdminUser).passwordHash === 'string' &&
    typeof (obj as AdminUser).role === 'string' &&
    typeof (obj as AdminUser).isActive === 'boolean'
  );
}

export function isValidAdminRole(role: string): role is AdminRole {
  return Object.keys(ROLE_HIERARCHY).includes(role);
}

export function hasHigherRole(userRole: AdminRole, targetRole: AdminRole): boolean {
  return ROLE_HIERARCHY[userRole] > ROLE_HIERARCHY[targetRole];
}

export function hasEqualOrHigherRole(userRole: AdminRole, targetRole: AdminRole): boolean {
  return ROLE_HIERARCHY[userRole] >= ROLE_HIERARCHY[targetRole];
}
