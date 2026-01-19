/**
 * Security Utilities
 *
 * Timing-safe comparison, IP hashing, and other security utilities.
 *
 * @module @tinyland/auth/core/security
 */
/**
 * Perform constant-time string comparison
 *
 * Prevents timing attacks by ensuring all comparisons take the same time
 * regardless of where strings differ.
 */
export declare function constantTimeCompare(a: string, b: string): boolean;
/**
 * Perform timing-safe verification with normalized response time
 *
 * Ensures all verifications take at least a minimum time, preventing
 * attackers from distinguishing between different failure modes.
 */
export declare function timingSafeVerify(verifyFn: () => Promise<boolean>, targetTimeMs?: number): Promise<boolean>;
/**
 * Timing-safe database query wrapper
 *
 * Ensures database queries take constant time regardless of result.
 */
export declare function timingSafeQuery<T>(queryFn: () => Promise<T | null>, minimumTimeMs?: number): Promise<T | null>;
/**
 * Generate timing-safe error responses
 */
export declare function timingSafeError(_errorType: string): string;
/**
 * Hash an IP address for privacy-compliant storage
 *
 * Uses SHA-256 to create a one-way hash that allows correlation
 * without storing the actual IP address.
 */
export declare function hashIp(ip: string, salt?: string): string;
/**
 * Mask an IP address for display purposes
 *
 * IPv4: 192.168.1.100 -> 192.168.*.*
 * IPv6: 2001:db8::1 -> 2001:db8:*:*:*:*:*:*
 */
export declare function maskIp(ip: string): string;
/**
 * Validate password strength
 */
export interface PasswordValidationResult {
    valid: boolean;
    errors: string[];
}
export interface PasswordPolicy {
    minLength: number;
    requireUppercase: boolean;
    requireLowercase: boolean;
    requireNumbers: boolean;
    requireSpecialChars: boolean;
}
export declare function validatePassword(password: string, policy: PasswordPolicy): PasswordValidationResult;
/**
 * Timing attack prevention metrics
 */
export declare class TimingMetrics {
    private measurements;
    private maxMeasurements;
    record(durationMs: number): void;
    getStats(): {
        mean: number;
        min: number;
        max: number;
        stdDev: number;
        variance: number;
    };
    isConsistent(maxVarianceMs?: number): boolean;
    reset(): void;
}
export declare const timingMetrics: TimingMetrics;
export { hashPassword, verifyPassword, needsRehash, getHashRounds, generateSecurePassword, type PasswordHashConfig, } from './password.js';
//# sourceMappingURL=index.d.ts.map