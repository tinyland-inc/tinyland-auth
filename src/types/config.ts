/**
 * Authentication Configuration Types
 *
 * @module @tinyland/auth/types/config
 */

export interface AuthConfig {
  /** Application name for display */
  appName: string;
  /** Base URL of the application */
  appUrl: string;
  /** Whether running in development mode */
  isDevelopment: boolean;

  /** TOTP configuration */
  totp: TOTPConfig;
  /** Session configuration */
  session: SessionConfig;
  /** Password policy configuration */
  password: PasswordConfig;
  /** Rate limiting configuration */
  rateLimit: RateLimitConfig;
  /** Invitation configuration */
  invitation: InvitationConfig;
  /** Backup codes configuration */
  backupCodes: BackupCodesConfig;
  /** Security configuration */
  security: SecurityConfig;
}

export interface TOTPConfig {
  /** Whether TOTP is enabled */
  enabled: boolean;
  /** Issuer name for authenticator apps */
  issuer: string;
  /** Encryption key for TOTP secrets */
  encryptionKey: string;
  /** Whether development mode features are enabled */
  devMode: boolean;
  /** Number of digits in TOTP code */
  digits: number;
  /** Time period in seconds */
  period: number;
  /** Hash algorithm */
  algorithm: 'SHA1' | 'SHA256' | 'SHA512';
  /** Time window tolerance for clock drift */
  window: number;
  /** Secret key length */
  secretLength: number;
  /** Number of backup codes to generate */
  backupCodesCount: number;
}

export interface SessionConfig {
  /** Maximum session age in milliseconds */
  maxAge: number;
  /** Cookie name for session ID */
  cookieName: string;
  /** Whether to use secure cookies */
  secureCookie: boolean;
  /** SameSite cookie attribute */
  sameSite: 'strict' | 'lax' | 'none';
  /** Whether cookie is httpOnly */
  httpOnly: boolean;
  /** Session renewal threshold in milliseconds */
  renewThreshold: number;
  /** Maximum concurrent sessions per user */
  maxConcurrentSessions: number;
  /** Remember me duration in milliseconds */
  rememberMeDuration: number;
}

export interface PasswordConfig {
  /** Minimum password length */
  minLength: number;
  /** Require uppercase letters */
  requireUppercase: boolean;
  /** Require lowercase letters */
  requireLowercase: boolean;
  /** Require numbers */
  requireNumbers: boolean;
  /** Require special characters */
  requireSpecialChars: boolean;
  /** bcrypt rounds for hashing */
  bcryptRounds: number;
}

export interface RateLimitConfig {
  /** Maximum login attempts */
  maxLoginAttempts: number;
  /** Lockout duration in milliseconds */
  lockoutDuration: number;
  /** Sliding window in milliseconds */
  slidingWindow: number;
  /** Maximum invitations per hour */
  maxInvitationsPerHour: number;
}

export interface InvitationConfig {
  /** Default invitation expiry in hours */
  defaultExpiryHours: number;
  /** Maximum active invitations */
  maxActiveInvitations: number;
  /** Allow email override on acceptance */
  allowEmailOverride: boolean;
}

export interface BackupCodesConfig {
  /** Number of backup codes to generate */
  count: number;
  /** Length of each code segment */
  length: number;
  /** Format regex for validation */
  format: RegExp;
}

export interface SecurityConfig {
  /** Enable audit logging */
  auditLogging: boolean;
  /** Enable session rotation on privilege escalation */
  sessionRotation: boolean;
  /** Enable IP-based session validation */
  ipValidation: boolean;
  /** Account lockout settings */
  accountLockout: {
    enabled: boolean;
    threshold: number;
    duration: number;
  };
  /** Re-authentication requirements */
  reAuthRequired: {
    enabled: boolean;
    operations: string[];
    timeout: number;
  };
}

/**
 * Default authentication configuration
 */
export const DEFAULT_AUTH_CONFIG: AuthConfig = {
  appName: 'Tinyland.dev',
  appUrl: 'http://localhost:9080',
  isDevelopment: process.env.NODE_ENV === 'development',

  totp: {
    enabled: true,
    issuer: 'Tinyland.dev',
    encryptionKey: '',
    devMode: false,
    digits: 6,
    period: 30,
    algorithm: 'SHA1',
    window: 1,
    secretLength: 32,
    backupCodesCount: 8,
  },

  session: {
    maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    cookieName: 'sessionId',
    secureCookie: true,
    sameSite: 'lax',
    httpOnly: true,
    renewThreshold: 24 * 60 * 60 * 1000, // 1 day
    maxConcurrentSessions: 5,
    rememberMeDuration: 30 * 24 * 60 * 60 * 1000, // 30 days
  },

  password: {
    minLength: 12,
    requireUppercase: true,
    requireLowercase: true,
    requireNumbers: true,
    requireSpecialChars: true,
    bcryptRounds: 12,
  },

  rateLimit: {
    maxLoginAttempts: 5,
    lockoutDuration: 15 * 60 * 1000, // 15 minutes
    slidingWindow: 60 * 60 * 1000, // 1 hour
    maxInvitationsPerHour: 10,
  },

  invitation: {
    defaultExpiryHours: 72,
    maxActiveInvitations: 50,
    allowEmailOverride: true,
  },

  backupCodes: {
    count: 10,
    length: 8,
    format: /^[A-Z0-9]{4}-[A-Z0-9]{4}$/,
  },

  security: {
    auditLogging: true,
    sessionRotation: true,
    ipValidation: false,
    accountLockout: {
      enabled: true,
      threshold: 5,
      duration: 30 * 60 * 1000, // 30 minutes
    },
    reAuthRequired: {
      enabled: true,
      operations: ['deleteUser', 'changeRole', 'resetTOTP'],
      timeout: 5 * 60 * 1000, // 5 minutes
    },
  },
};

/**
 * Create a configuration object with defaults
 */
export function createAuthConfig(overrides: Partial<AuthConfig> = {}): AuthConfig {
  return {
    ...DEFAULT_AUTH_CONFIG,
    ...overrides,
    totp: { ...DEFAULT_AUTH_CONFIG.totp, ...overrides.totp },
    session: { ...DEFAULT_AUTH_CONFIG.session, ...overrides.session },
    password: { ...DEFAULT_AUTH_CONFIG.password, ...overrides.password },
    rateLimit: { ...DEFAULT_AUTH_CONFIG.rateLimit, ...overrides.rateLimit },
    invitation: { ...DEFAULT_AUTH_CONFIG.invitation, ...overrides.invitation },
    backupCodes: { ...DEFAULT_AUTH_CONFIG.backupCodes, ...overrides.backupCodes },
    security: { ...DEFAULT_AUTH_CONFIG.security, ...overrides.security },
  };
}
