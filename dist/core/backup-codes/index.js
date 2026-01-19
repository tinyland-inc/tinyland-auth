/**
 * Backup Codes Service
 *
 * Manages emergency access codes for TOTP recovery.
 * Uses SHA-256 hashing for secure storage.
 *
 * @module @tinyland/auth/core/backup-codes
 */
import { randomBytes, createHash } from 'crypto';
export const DEFAULT_BACKUP_CODES_CONFIG = {
    count: 10,
    format: /^[A-Z0-9]{4}-[A-Z0-9]{4}$/,
};
/**
 * Generate new backup codes
 *
 * @param count - Number of codes to generate
 * @returns Array of plain-text backup codes in XXXX-XXXX format
 */
export function generateBackupCodes(count = 10) {
    const codes = [];
    for (let i = 0; i < count; i++) {
        const part1 = randomBytes(2).toString('hex').toUpperCase();
        const part2 = randomBytes(2).toString('hex').toUpperCase();
        codes.push(`${part1}-${part2}`);
    }
    return codes;
}
/**
 * Hash a backup code for secure storage
 *
 * @param code - Plain-text backup code
 * @returns SHA-256 hash of the normalized code
 */
export function hashBackupCode(code) {
    const normalized = code.toUpperCase().replace(/[^A-Z0-9]/g, '');
    return createHash('sha256').update(normalized).digest('hex');
}
/**
 * Create a backup code set from plain-text codes
 *
 * @param userId - User ID
 * @param codes - Array of plain-text codes
 * @returns BackupCodeSet with hashed codes
 */
export function createBackupCodeSet(userId, codes) {
    const hashedCodes = codes.map(code => ({
        id: randomBytes(16).toString('hex'),
        hash: hashBackupCode(code),
        used: false,
    }));
    return {
        userId,
        codes: hashedCodes,
        generatedAt: new Date().toISOString(),
    };
}
/**
 * Verify a backup code against a code set
 *
 * @param codeSet - The user's backup code set
 * @param code - The code to verify
 * @returns Object with verification result and updated code set
 */
export function verifyBackupCode(codeSet, code) {
    const hashedCode = hashBackupCode(code);
    // Find matching unused code
    const matchingCodeIndex = codeSet.codes.findIndex(c => c.hash === hashedCode && !c.used);
    if (matchingCodeIndex === -1) {
        return {
            valid: false,
            codeSet,
            codesRemaining: codeSet.codes.filter(c => !c.used).length,
        };
    }
    // Mark code as used
    const updatedCodes = [...codeSet.codes];
    updatedCodes[matchingCodeIndex] = {
        ...updatedCodes[matchingCodeIndex],
        used: true,
        usedAt: new Date().toISOString(),
    };
    const updatedCodeSet = {
        ...codeSet,
        codes: updatedCodes,
        lastUsedAt: new Date().toISOString(),
    };
    return {
        valid: true,
        codeSet: updatedCodeSet,
        codesRemaining: updatedCodes.filter(c => !c.used).length,
    };
}
/**
 * Get count of remaining unused backup codes
 *
 * @param codeSet - The user's backup code set
 * @returns Number of remaining codes
 */
export function getRemainingCodesCount(codeSet) {
    if (!codeSet)
        return 0;
    return codeSet.codes.filter(c => !c.used).length;
}
/**
 * Check if user has any unused backup codes
 *
 * @param codeSet - The user's backup code set
 * @returns true if there are unused codes
 */
export function hasUnusedCodes(codeSet) {
    return getRemainingCodesCount(codeSet) > 0;
}
/**
 * Validate backup code format
 *
 * @param code - Code to validate
 * @param format - Regex format to validate against
 * @returns true if code matches format
 */
export function isValidCodeFormat(code, format = DEFAULT_BACKUP_CODES_CONFIG.format) {
    const normalized = code.toUpperCase().replace(/[^A-Z0-9-]/g, '');
    return format.test(normalized);
}
/**
 * Format codes for display
 *
 * @param codes - Array of backup codes
 * @returns Array of numbered codes for display
 */
export function formatCodesForDisplay(codes) {
    return codes.map((code, index) => {
        const num = (index + 1).toString().padStart(2, '0');
        return `${num}. ${code}`;
    });
}
/**
 * Check if backup codes should be regenerated
 *
 * @param codeSet - The user's backup code set
 * @param threshold - Minimum codes before regeneration is recommended
 * @returns true if regeneration is recommended
 */
export function shouldRegenerateCodes(codeSet, threshold = 2) {
    return getRemainingCodesCount(codeSet) <= threshold;
}
//# sourceMappingURL=index.js.map