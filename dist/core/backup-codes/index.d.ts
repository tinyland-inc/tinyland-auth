/**
 * Backup Codes Service
 *
 * Manages emergency access codes for TOTP recovery.
 * Uses SHA-256 hashing for secure storage.
 *
 * @module @tinyland/auth/core/backup-codes
 */
import type { BackupCodeSet } from '../../types/auth.js';
export interface BackupCodesConfig {
    /** Number of codes to generate */
    count: number;
    /** Code format regex for validation */
    format: RegExp;
}
export declare const DEFAULT_BACKUP_CODES_CONFIG: BackupCodesConfig;
/**
 * Generate new backup codes
 *
 * @param count - Number of codes to generate
 * @returns Array of plain-text backup codes in XXXX-XXXX format
 */
export declare function generateBackupCodes(count?: number): string[];
/**
 * Hash a backup code for secure storage
 *
 * @param code - Plain-text backup code
 * @returns SHA-256 hash of the normalized code
 */
export declare function hashBackupCode(code: string): string;
/**
 * Create a backup code set from plain-text codes
 *
 * @param userId - User ID
 * @param codes - Array of plain-text codes
 * @returns BackupCodeSet with hashed codes
 */
export declare function createBackupCodeSet(userId: string, codes: string[]): BackupCodeSet;
/**
 * Verify a backup code against a code set
 *
 * @param codeSet - The user's backup code set
 * @param code - The code to verify
 * @returns Object with verification result and updated code set
 */
export declare function verifyBackupCode(codeSet: BackupCodeSet, code: string): {
    valid: boolean;
    codeSet: BackupCodeSet;
    codesRemaining: number;
};
/**
 * Get count of remaining unused backup codes
 *
 * @param codeSet - The user's backup code set
 * @returns Number of remaining codes
 */
export declare function getRemainingCodesCount(codeSet: BackupCodeSet | null): number;
/**
 * Check if user has any unused backup codes
 *
 * @param codeSet - The user's backup code set
 * @returns true if there are unused codes
 */
export declare function hasUnusedCodes(codeSet: BackupCodeSet | null): boolean;
/**
 * Validate backup code format
 *
 * @param code - Code to validate
 * @param format - Regex format to validate against
 * @returns true if code matches format
 */
export declare function isValidCodeFormat(code: string, format?: RegExp): boolean;
/**
 * Format codes for display
 *
 * @param codes - Array of backup codes
 * @returns Array of numbered codes for display
 */
export declare function formatCodesForDisplay(codes: string[]): string[];
/**
 * Check if backup codes should be regenerated
 *
 * @param codeSet - The user's backup code set
 * @param threshold - Minimum codes before regeneration is recommended
 * @returns true if regeneration is recommended
 */
export declare function shouldRegenerateCodes(codeSet: BackupCodeSet | null, threshold?: number): boolean;
//# sourceMappingURL=index.d.ts.map