/**
 * Authentication Configuration Types
 *
 * @module @tinyland/auth/types/config
 */
/**
 * Default authentication configuration
 */
export const DEFAULT_AUTH_CONFIG = {
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
export function createAuthConfig(overrides = {}) {
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
//# sourceMappingURL=config.js.map