/**
 * Password Hashing Utilities
 *
 * Provides bcrypt-based password hashing with configurable cost factor.
 * Uses timing-safe comparison for verification.
 *
 * @module @tinyland/auth/core/security/password
 */

import * as bcrypt from 'bcryptjs';

/**
 * Password hashing configuration
 */
export interface PasswordHashConfig {
  /** bcrypt cost factor (rounds). Higher = slower but more secure. Default: 12 */
  rounds: number;
}

const DEFAULT_CONFIG: PasswordHashConfig = {
  rounds: 12,
};

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
export async function hashPassword(
  password: string,
  config: Partial<PasswordHashConfig> = {}
): Promise<string> {
  const { rounds } = { ...DEFAULT_CONFIG, ...config };

  if (rounds < 4 || rounds > 31) {
    throw new Error('bcrypt rounds must be between 4 and 31');
  }

  return bcrypt.hash(password, rounds);
}

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
export async function verifyPassword(
  password: string,
  hash: string
): Promise<boolean> {
  // bcrypt.compare is timing-safe
  return bcrypt.compare(password, hash);
}

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
export function needsRehash(hash: string, desiredRounds: number): boolean {
  // bcrypt hash format: $2a$XX$... where XX is the rounds
  const match = hash.match(/^\$2[aby]?\$(\d+)\$/);
  if (!match) {
    return true; // Invalid hash format
  }

  const currentRounds = parseInt(match[1], 10);
  return currentRounds < desiredRounds;
}

/**
 * Get the cost factor (rounds) from a bcrypt hash
 *
 * @param hash - bcrypt hash
 * @returns The number of rounds, or null if invalid
 */
export function getHashRounds(hash: string): number | null {
  const match = hash.match(/^\$2[aby]?\$(\d+)\$/);
  return match ? parseInt(match[1], 10) : null;
}

/**
 * Generate a secure random password
 *
 * Useful for temporary passwords or initial setup.
 *
 * @param length - Password length (default: 16)
 * @param options - Character set options
 * @returns Randomly generated password
 */
export function generateSecurePassword(
  length: number = 16,
  options: {
    includeUppercase?: boolean;
    includeLowercase?: boolean;
    includeNumbers?: boolean;
    includeSpecial?: boolean;
  } = {}
): string {
  const {
    includeUppercase = true,
    includeLowercase = true,
    includeNumbers = true,
    includeSpecial = true,
  } = options;

  let charset = '';
  if (includeUppercase) charset += 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  if (includeLowercase) charset += 'abcdefghijklmnopqrstuvwxyz';
  if (includeNumbers) charset += '0123456789';
  if (includeSpecial) charset += '!@#$%^&*()_+-=[]{}|;:,.<>?';

  if (charset.length === 0) {
    charset = 'abcdefghijklmnopqrstuvwxyz0123456789';
  }

  const { randomBytes } = require('crypto');
  const bytes = randomBytes(length);
  let password = '';

  for (let i = 0; i < length; i++) {
    password += charset[bytes[i] % charset.length];
  }

  return password;
}
