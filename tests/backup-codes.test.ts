/**
 * Backup Codes Unit Tests
 *
 * Tests for backup code generation and verification.
 */

import { describe, it, expect } from 'vitest';
import {
  generateBackupCodes,
  hashBackupCode,
  createBackupCodeSet,
  verifyBackupCode,
  getRemainingCodesCount,
  hasUnusedCodes,
  isValidCodeFormat,
  formatCodesForDisplay,
  shouldRegenerateCodes,
  DEFAULT_BACKUP_CODES_CONFIG,
} from '../src/core/backup-codes/index.js';

describe('Backup Codes', () => {
  describe('generateBackupCodes', () => {
    it('should generate the specified number of codes', () => {
      const codes = generateBackupCodes(10);
      expect(codes).toHaveLength(10);
    });

    it('should generate unique codes', () => {
      const codes = generateBackupCodes(100);
      const uniqueCodes = new Set(codes);
      expect(uniqueCodes.size).toBe(100);
    });

    it('should generate codes in XXXX-XXXX format', () => {
      const codes = generateBackupCodes(10);
      codes.forEach(code => {
        expect(code).toMatch(/^[A-Z0-9]{4}-[A-Z0-9]{4}$/);
      });
    });

    it('should use default count when not specified', () => {
      const codes = generateBackupCodes();
      expect(codes).toHaveLength(10);
    });
  });

  describe('hashBackupCode', () => {
    it('should return a hex string', () => {
      const hash = hashBackupCode('ABCD-1234');
      expect(hash).toMatch(/^[a-f0-9]{64}$/); // SHA-256 = 64 hex chars
    });

    it('should return consistent hashes for the same code', () => {
      const hash1 = hashBackupCode('ABCD-1234');
      const hash2 = hashBackupCode('ABCD-1234');
      expect(hash1).toBe(hash2);
    });

    it('should return different hashes for different codes', () => {
      const hash1 = hashBackupCode('ABCD-1234');
      const hash2 = hashBackupCode('EFGH-5678');
      expect(hash1).not.toBe(hash2);
    });

    it('should normalize codes (ignore case and separators)', () => {
      const hash1 = hashBackupCode('ABCD-1234');
      const hash2 = hashBackupCode('abcd-1234');
      const hash3 = hashBackupCode('ABCD1234');
      expect(hash1).toBe(hash2);
      expect(hash1).toBe(hash3);
    });
  });

  describe('createBackupCodeSet', () => {
    it('should create a code set with hashed codes', () => {
      const plainCodes = ['ABCD-1234', 'EFGH-5678'];
      const codeSet = createBackupCodeSet('user-1', plainCodes);

      expect(codeSet.userId).toBe('user-1');
      expect(codeSet.codes).toHaveLength(2);
      expect(codeSet.generatedAt).toBeTruthy();

      // Verify codes are hashed
      codeSet.codes.forEach(code => {
        expect(code.hash).toMatch(/^[a-f0-9]{64}$/);
        expect(code.used).toBe(false);
        expect(code.id).toBeTruthy();
      });
    });
  });

  describe('verifyBackupCode', () => {
    it('should verify a valid unused code', () => {
      const plainCodes = generateBackupCodes(3);
      const codeSet = createBackupCodeSet('user-1', plainCodes);

      const result = verifyBackupCode(codeSet, plainCodes[0]);

      expect(result.valid).toBe(true);
      expect(result.codesRemaining).toBe(2);
    });

    it('should reject an invalid code', () => {
      const plainCodes = generateBackupCodes(3);
      const codeSet = createBackupCodeSet('user-1', plainCodes);

      const result = verifyBackupCode(codeSet, 'XXXX-YYYY');

      expect(result.valid).toBe(false);
      expect(result.codesRemaining).toBe(3);
    });

    it('should mark code as used after verification', () => {
      const plainCodes = generateBackupCodes(3);
      const codeSet = createBackupCodeSet('user-1', plainCodes);

      const result = verifyBackupCode(codeSet, plainCodes[0]);

      expect(result.valid).toBe(true);

      // Try to use the same code again
      const result2 = verifyBackupCode(result.codeSet, plainCodes[0]);
      expect(result2.valid).toBe(false);
    });

    it('should update lastUsedAt on successful verification', () => {
      const plainCodes = generateBackupCodes(3);
      const codeSet = createBackupCodeSet('user-1', plainCodes);

      expect(codeSet.lastUsedAt).toBeUndefined();

      const result = verifyBackupCode(codeSet, plainCodes[0]);
      expect(result.codeSet.lastUsedAt).toBeTruthy();
    });
  });

  describe('getRemainingCodesCount', () => {
    it('should return the count of unused codes', () => {
      const plainCodes = generateBackupCodes(5);
      const codeSet = createBackupCodeSet('user-1', plainCodes);

      expect(getRemainingCodesCount(codeSet)).toBe(5);

      // Use one code
      const result = verifyBackupCode(codeSet, plainCodes[0]);
      expect(getRemainingCodesCount(result.codeSet)).toBe(4);
    });

    it('should return 0 for null code set', () => {
      expect(getRemainingCodesCount(null)).toBe(0);
    });
  });

  describe('hasUnusedCodes', () => {
    it('should return true when codes are available', () => {
      const codeSet = createBackupCodeSet('user-1', generateBackupCodes(3));
      expect(hasUnusedCodes(codeSet)).toBe(true);
    });

    it('should return false when all codes are used', () => {
      const plainCodes = generateBackupCodes(1);
      let codeSet = createBackupCodeSet('user-1', plainCodes);

      const result = verifyBackupCode(codeSet, plainCodes[0]);
      expect(hasUnusedCodes(result.codeSet)).toBe(false);
    });

    it('should return false for null code set', () => {
      expect(hasUnusedCodes(null)).toBe(false);
    });
  });

  describe('isValidCodeFormat', () => {
    it('should accept valid XXXX-XXXX format', () => {
      expect(isValidCodeFormat('ABCD-1234')).toBe(true);
      expect(isValidCodeFormat('1234-ABCD')).toBe(true);
      expect(isValidCodeFormat('A1B2-C3D4')).toBe(true);
    });

    it('should accept lowercase codes', () => {
      expect(isValidCodeFormat('abcd-1234')).toBe(true);
    });

    it('should reject invalid formats', () => {
      expect(isValidCodeFormat('ABCD1234')).toBe(false); // No separator
      expect(isValidCodeFormat('ABC-1234')).toBe(false); // Too short
      expect(isValidCodeFormat('ABCDE-12345')).toBe(false); // Too long
      expect(isValidCodeFormat('')).toBe(false);
    });
  });

  describe('formatCodesForDisplay', () => {
    it('should number codes starting from 01', () => {
      const codes = ['ABCD-1234', 'EFGH-5678', 'IJKL-9012'];
      const formatted = formatCodesForDisplay(codes);

      expect(formatted[0]).toBe('01. ABCD-1234');
      expect(formatted[1]).toBe('02. EFGH-5678');
      expect(formatted[2]).toBe('03. IJKL-9012');
    });

    it('should handle double-digit numbers', () => {
      const codes = generateBackupCodes(12);
      const formatted = formatCodesForDisplay(codes);

      expect(formatted[9]).toMatch(/^10\./);
      expect(formatted[11]).toMatch(/^12\./);
    });
  });

  describe('shouldRegenerateCodes', () => {
    it('should return true when codes are below threshold', () => {
      const plainCodes = generateBackupCodes(3);
      let codeSet = createBackupCodeSet('user-1', plainCodes);

      // Use codes until only 2 remain
      codeSet = verifyBackupCode(codeSet, plainCodes[0]).codeSet;

      expect(shouldRegenerateCodes(codeSet, 2)).toBe(true);
    });

    it('should return false when codes are above threshold', () => {
      const codeSet = createBackupCodeSet('user-1', generateBackupCodes(10));
      expect(shouldRegenerateCodes(codeSet, 2)).toBe(false);
    });

    it('should return true for null code set', () => {
      expect(shouldRegenerateCodes(null)).toBe(true);
    });
  });

  describe('DEFAULT_BACKUP_CODES_CONFIG', () => {
    it('should have sensible defaults', () => {
      expect(DEFAULT_BACKUP_CODES_CONFIG.count).toBe(10);
      expect(DEFAULT_BACKUP_CODES_CONFIG.format).toBeInstanceOf(RegExp);
      expect(DEFAULT_BACKUP_CODES_CONFIG.format.test('ABCD-1234')).toBe(true);
    });
  });
});
