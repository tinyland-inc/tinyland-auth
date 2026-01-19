/**
 * Security Utilities
 *
 * Timing-safe comparison, IP hashing, and other security utilities.
 *
 * @module @tinyland/auth/core/security
 */
import { timingSafeEqual, createHash } from 'crypto';
/**
 * Sleep for a specified number of milliseconds
 */
async function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}
/**
 * Perform constant-time string comparison
 *
 * Prevents timing attacks by ensuring all comparisons take the same time
 * regardless of where strings differ.
 */
export function constantTimeCompare(a, b) {
    const maxLength = Math.max(a.length, b.length);
    const paddedA = a.padEnd(maxLength, '\0');
    const paddedB = b.padEnd(maxLength, '\0');
    const bufA = Buffer.from(paddedA, 'utf-8');
    const bufB = Buffer.from(paddedB, 'utf-8');
    try {
        return timingSafeEqual(bufA, bufB);
    }
    catch {
        return false;
    }
}
/**
 * Perform timing-safe verification with normalized response time
 *
 * Ensures all verifications take at least a minimum time, preventing
 * attackers from distinguishing between different failure modes.
 */
export async function timingSafeVerify(verifyFn, targetTimeMs = 100) {
    const startTime = Date.now();
    try {
        const result = await verifyFn();
        const elapsed = Date.now() - startTime;
        if (elapsed < targetTimeMs) {
            await sleep(targetTimeMs - elapsed);
        }
        return result;
    }
    catch (error) {
        const elapsed = Date.now() - startTime;
        if (elapsed < targetTimeMs) {
            await sleep(targetTimeMs - elapsed);
        }
        throw error;
    }
}
/**
 * Timing-safe database query wrapper
 *
 * Ensures database queries take constant time regardless of result.
 */
export async function timingSafeQuery(queryFn, minimumTimeMs = 50) {
    const startTime = Date.now();
    try {
        const result = await queryFn();
        const elapsed = Date.now() - startTime;
        if (elapsed < minimumTimeMs) {
            await sleep(minimumTimeMs - elapsed);
        }
        return result;
    }
    catch (error) {
        const elapsed = Date.now() - startTime;
        if (elapsed < minimumTimeMs) {
            await sleep(minimumTimeMs - elapsed);
        }
        throw error;
    }
}
/**
 * Generate timing-safe error responses
 */
export function timingSafeError(_errorType) {
    return 'Invalid credentials';
}
/**
 * Hash an IP address for privacy-compliant storage
 *
 * Uses SHA-256 to create a one-way hash that allows correlation
 * without storing the actual IP address.
 */
export function hashIp(ip, salt) {
    const data = salt ? `${ip}:${salt}` : ip;
    return createHash('sha256').update(data).digest('hex').substring(0, 16);
}
/**
 * Mask an IP address for display purposes
 *
 * IPv4: 192.168.1.100 -> 192.168.*.*
 * IPv6: 2001:db8::1 -> 2001:db8:*:*:*:*:*:*
 */
export function maskIp(ip) {
    if (ip.includes(':')) {
        // IPv6
        const parts = ip.split(':');
        if (parts.length >= 2) {
            return `${parts[0]}:${parts[1]}:*:*:*:*:*:*`;
        }
        return '*:*:*:*:*:*:*:*';
    }
    // IPv4
    const parts = ip.split('.');
    if (parts.length === 4) {
        return `${parts[0]}.${parts[1]}.*.*`;
    }
    return '*.*.*.*';
}
export function validatePassword(password, policy) {
    const errors = [];
    if (password.length < policy.minLength) {
        errors.push(`Password must be at least ${policy.minLength} characters`);
    }
    if (policy.requireUppercase && !/[A-Z]/.test(password)) {
        errors.push('Password must contain at least one uppercase letter');
    }
    if (policy.requireLowercase && !/[a-z]/.test(password)) {
        errors.push('Password must contain at least one lowercase letter');
    }
    if (policy.requireNumbers && !/[0-9]/.test(password)) {
        errors.push('Password must contain at least one number');
    }
    if (policy.requireSpecialChars && !/[!@#$%^&*()_+\-=[\]{};':"\\|,.<>/?]/.test(password)) {
        errors.push('Password must contain at least one special character');
    }
    return {
        valid: errors.length === 0,
        errors,
    };
}
/**
 * Timing attack prevention metrics
 */
export class TimingMetrics {
    measurements = [];
    maxMeasurements = 1000;
    record(durationMs) {
        this.measurements.push(durationMs);
        if (this.measurements.length > this.maxMeasurements) {
            this.measurements.shift();
        }
    }
    getStats() {
        if (this.measurements.length === 0) {
            return { mean: 0, min: 0, max: 0, stdDev: 0, variance: 0 };
        }
        const mean = this.measurements.reduce((a, b) => a + b, 0) / this.measurements.length;
        const variance = this.measurements.reduce((sum, val) => sum + Math.pow(val - mean, 2), 0) / this.measurements.length;
        const stdDev = Math.sqrt(variance);
        return {
            mean,
            min: Math.min(...this.measurements),
            max: Math.max(...this.measurements),
            stdDev,
            variance,
        };
    }
    isConsistent(maxVarianceMs = 10) {
        const stats = this.getStats();
        return stats.variance <= maxVarianceMs;
    }
    reset() {
        this.measurements = [];
    }
}
export const timingMetrics = new TimingMetrics();
// Password hashing utilities
export { hashPassword, verifyPassword, needsRehash, getHashRounds, generateSecurePassword, } from './password.js';
//# sourceMappingURL=index.js.map