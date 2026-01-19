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
export declare const DEFAULT_AUTH_CONFIG: AuthConfig;
/**
 * Create a configuration object with defaults
 */
export declare function createAuthConfig(overrides?: Partial<AuthConfig>): AuthConfig;
//# sourceMappingURL=config.d.ts.map