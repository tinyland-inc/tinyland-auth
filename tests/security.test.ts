





import { describe, it, expect } from 'vitest';
import {
  constantTimeCompare,
  hashIp,
  maskIp,
  validatePassword,
} from '../src/core/security/index.js';

describe('Security Utilities', () => {
  describe('constantTimeCompare', () => {
    it('should return true for identical strings', () => {
      expect(constantTimeCompare('abc123', 'abc123')).toBe(true);
      expect(constantTimeCompare('', '')).toBe(true);
      expect(constantTimeCompare('x', 'x')).toBe(true);
    });

    it('should return false for different strings', () => {
      expect(constantTimeCompare('abc123', 'abc124')).toBe(false);
      expect(constantTimeCompare('abc', 'abcd')).toBe(false);
      expect(constantTimeCompare('', 'x')).toBe(false);
    });

    it('should return false for different length strings', () => {
      expect(constantTimeCompare('short', 'longer string')).toBe(false);
    });

    it('should be case sensitive', () => {
      expect(constantTimeCompare('ABC', 'abc')).toBe(false);
    });
  });

  describe('hashIp', () => {
    it('should return a consistent hash for the same IP', () => {
      const hash1 = hashIp('192.168.1.1');
      const hash2 = hashIp('192.168.1.1');
      expect(hash1).toBe(hash2);
    });

    it('should return different hashes for different IPs', () => {
      const hash1 = hashIp('192.168.1.1');
      const hash2 = hashIp('192.168.1.2');
      expect(hash1).not.toBe(hash2);
    });

    it('should return different hashes with different salts', () => {
      const hash1 = hashIp('192.168.1.1', 'salt1');
      const hash2 = hashIp('192.168.1.1', 'salt2');
      expect(hash1).not.toBe(hash2);
    });

    it('should return a hex string', () => {
      const hash = hashIp('192.168.1.1');
      expect(hash).toMatch(/^[a-f0-9]+$/);
    });

    it('should return a truncated hash (16 chars)', () => {
      const hash = hashIp('192.168.1.1');
      expect(hash.length).toBe(16);
    });
  });

  describe('maskIp', () => {
    it('should mask IPv4 addresses', () => {
      expect(maskIp('192.168.1.100')).toBe('192.168.*.*');
      expect(maskIp('10.0.0.1')).toBe('10.0.*.*');
    });

    it('should mask IPv6 addresses', () => {
      const masked = maskIp('2001:0db8:85a3:0000:0000:8a2e:0370:7334');
      expect(masked).toBe('2001:0db8:*:*:*:*:*:*');
    });

    it('should handle localhost', () => {
      expect(maskIp('127.0.0.1')).toBe('127.0.*.*');
    });

    it('should handle empty or invalid input gracefully', () => {
      expect(maskIp('')).toBe('*.*.*.*');
      expect(maskIp('invalid')).toBe('*.*.*.*');
    });
  });

  describe('validatePassword', () => {
    const defaultPolicy = {
      minLength: 12,
      requireUppercase: true,
      requireLowercase: true,
      requireNumbers: true,
      requireSpecialChars: true,
    };

    it('should accept valid passwords', () => {
      const result = validatePassword('SecurePass123!', defaultPolicy);
      expect(result.valid).toBe(true);
      expect(result.errors).toHaveLength(0);
    });

    it('should reject passwords that are too short', () => {
      const result = validatePassword('Short1!', defaultPolicy);
      expect(result.valid).toBe(false);
      expect(result.errors).toContain('Password must be at least 12 characters');
    });

    it('should reject passwords without uppercase', () => {
      const result = validatePassword('lowercase123!abc', defaultPolicy);
      expect(result.valid).toBe(false);
      expect(result.errors).toContain('Password must contain at least one uppercase letter');
    });

    it('should reject passwords without lowercase', () => {
      const result = validatePassword('UPPERCASE123!ABC', defaultPolicy);
      expect(result.valid).toBe(false);
      expect(result.errors).toContain('Password must contain at least one lowercase letter');
    });

    it('should reject passwords without numbers', () => {
      const result = validatePassword('NoNumbersHere!', defaultPolicy);
      expect(result.valid).toBe(false);
      expect(result.errors).toContain('Password must contain at least one number');
    });

    it('should reject passwords without special characters', () => {
      const result = validatePassword('NoSpecialChars123', defaultPolicy);
      expect(result.valid).toBe(false);
      expect(result.errors).toContain('Password must contain at least one special character');
    });

    it('should collect all validation errors', () => {
      const result = validatePassword('short', defaultPolicy);
      expect(result.valid).toBe(false);
      expect(result.errors.length).toBeGreaterThan(1);
    });

    it('should use custom policy settings', () => {
      const customPolicy = {
        minLength: 6,
        requireUppercase: false,
        requireLowercase: true,
        requireNumbers: false,
        requireSpecialChars: false,
      };
      const result = validatePassword('simple', customPolicy);
      expect(result.valid).toBe(true);
    });
  });
});
