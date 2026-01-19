/**
 * Password Hashing Utilities
 *
 * Provides bcrypt-based password hashing with configurable cost factor.
 * Uses timing-safe comparison for verification.
 *
 * @module @tinyland/auth/core/security/password
 */
/**
 * Password hashing configuration
 */
export interface PasswordHashConfig {
    /** bcrypt cost factor (rounds). Higher = slower but more secure. Default: 12 */
    rounds: number;
}
/**
 * Hash a password using bcrypt
 *
 * @param password - Plain text password to hash
 * @param config - Optional configuration (rounds)
 * @returns Promise resolving to the bcrypt hash
 *
 * @example
 * ```typescript
 * const hash = await hashPassword('mySecurePassword123!');
 * // Store hash in database
 * ```
 */
export declare function hashPassword(password: string, config?: Partial<PasswordHashConfig>): Promise<string>;
/**
 * Verify a password against a bcrypt hash
 *
 * Uses bcrypt's built-in timing-safe comparison.
 *
 * @param password - Plain text password to verify
 * @param hash - bcrypt hash to compare against
 * @returns Promise resolving to true if password matches
 *
 * @example
 * ```typescript
 * const isValid = await verifyPassword('userInput', storedHash);
 * if (isValid) {
 *   // Authentication successful
 * }
 * ```
 */
export declare function verifyPassword(password: string, hash: string): Promise<boolean>;
/**
 * Check if a password hash needs rehashing
 *
 * Useful when upgrading bcrypt rounds over time.
 *
 * @param hash - bcrypt hash to check
 * @param desiredRounds - Desired bcrypt rounds
 * @returns true if the hash should be regenerated
 *
 * @example
 * ```typescript
 * if (needsRehash(user.passwordHash, 14)) {
 *   // Upgrade hash after successful login
 *   user.passwordHash = await hashPassword(plainPassword, { rounds: 14 });
 * }
 * ```
 */
export declare function needsRehash(hash: string, desiredRounds: number): boolean;
/**
 * Get the cost factor (rounds) from a bcrypt hash
 *
 * @param hash - bcrypt hash
 * @returns The number of rounds, or null if invalid
 */
export declare function getHashRounds(hash: string): number | null;
/**
 * Generate a secure random password
 *
 * Useful for temporary passwords or initial setup.
 *
 * @param length - Password length (default: 16)
 * @param options - Character set options
 * @returns Randomly generated password
 */
export declare function generateSecurePassword(length?: number, options?: {
    includeUppercase?: boolean;
    includeLowercase?: boolean;
    includeNumbers?: boolean;
    includeSpecial?: boolean;
}): string;
//# sourceMappingURL=password.d.ts.map