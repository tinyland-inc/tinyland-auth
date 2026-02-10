/**
 * TOTP Compatibility Layer Unit Tests
 *
 * Tests for the standalone TOTP utility functions (compat layer).
 */

import { describe, it, expect } from 'vitest';
import {
  generateTOTPSecret,
  generateTOTPUri,
  generateTempPassword,
  generateTOTPQRCode,
  generateTOTPToken,
  getTOTPTimeRemaining,
} from '../src/totp/compat.js';

describe('TOTP Compatibility Layer', () => {
  describe('generateTOTPSecret', () => {
    it('should generate a base32-encoded secret', () => {
      const secret = generateTOTPSecret();
      expect(secret).toMatch(/^[A-Z2-7]+$/);
    });

    it('should generate unique secrets on successive calls', () => {
      const secret1 = generateTOTPSecret();
      const secret2 = generateTOTPSecret();
      expect(secret1).not.toBe(secret2);
    });

    it('should generate secrets with sufficient length', () => {
      const secret = generateTOTPSecret();
      // At least 16 base32 chars = 80 bits of entropy
      expect(secret.length).toBeGreaterThanOrEqual(16);
    });
  });

  describe('generateTOTPUri', () => {
    it('should generate a valid otpauth URI', () => {
      const secret = generateTOTPSecret();
      const uri = generateTOTPUri(secret, 'TestApp', 'user@example.com');

      expect(uri).toContain('otpauth://totp/');
      expect(uri).toContain(`secret=${secret}`);
      expect(uri).toContain('issuer=TestApp');
    });

    it('should URL-encode label and issuer', () => {
      const secret = generateTOTPSecret();
      const uri = generateTOTPUri(secret, 'My App', 'user name');

      expect(uri).toContain('issuer=My%20App');
      expect(uri).toContain('user%20name');
    });

    it('should throw on empty secret', () => {
      expect(() => generateTOTPUri('', 'App', 'user')).toThrow('Secret, issuer, and label are required');
    });

    it('should throw on empty issuer', () => {
      expect(() => generateTOTPUri('JBSWY3DPEHPK3PXP', '', 'user')).toThrow('Secret, issuer, and label are required');
    });

    it('should throw on empty label', () => {
      expect(() => generateTOTPUri('JBSWY3DPEHPK3PXP', 'App', '')).toThrow('Secret, issuer, and label are required');
    });

    it('should throw on invalid base32 secret', () => {
      expect(() => generateTOTPUri('not-base32!', 'App', 'user')).toThrow('Invalid base32 secret');
    });

    it('should include standard TOTP parameters', () => {
      const secret = generateTOTPSecret();
      const uri = generateTOTPUri(secret, 'App', 'user');

      expect(uri).toContain('algorithm=SHA1');
      expect(uri).toContain('digits=6');
      expect(uri).toContain('period=30');
    });
  });

  describe('generateTempPassword', () => {
    it('should generate a password of the requested length', () => {
      const password = generateTempPassword(12);
      expect(password.length).toBe(12);
    });

    it('should default to 8 characters', () => {
      const password = generateTempPassword();
      expect(password.length).toBe(8);
    });

    it('should throw if length is less than 8', () => {
      expect(() => generateTempPassword(5)).toThrow('Password must be at least 8 characters');
    });

    it('should contain uppercase, lowercase, and digits', () => {
      const password = generateTempPassword(16);
      expect(/[A-Z]/.test(password)).toBe(true);
      expect(/[a-z]/.test(password)).toBe(true);
      expect(/[0-9]/.test(password)).toBe(true);
    });

    it('should not contain ambiguous characters', () => {
      // Generate many passwords and check none contain O, 0, I, l, 1
      for (let i = 0; i < 50; i++) {
        const password = generateTempPassword(16);
        expect(password).not.toMatch(/[OIl01]/);
      }
    });

    it('should generate unique passwords', () => {
      const passwords = new Set<string>();
      for (let i = 0; i < 20; i++) {
        passwords.add(generateTempPassword(12));
      }
      // All 20 should be unique (collision is astronomically unlikely)
      expect(passwords.size).toBe(20);
    });
  });

  describe('generateTOTPQRCode', () => {
    it('should generate a data URL for a valid URI', async () => {
      const secret = generateTOTPSecret();
      const uri = generateTOTPUri(secret, 'App', 'user');
      const qrCode = await generateTOTPQRCode(uri);

      expect(qrCode).toMatch(/^data:image\/png;base64,/);
    });

    it('should generate different QR codes for different URIs', async () => {
      const secret1 = generateTOTPSecret();
      const secret2 = generateTOTPSecret();
      const uri1 = generateTOTPUri(secret1, 'App', 'user1');
      const uri2 = generateTOTPUri(secret2, 'App', 'user2');

      const qr1 = await generateTOTPQRCode(uri1);
      const qr2 = await generateTOTPQRCode(uri2);

      expect(qr1).not.toBe(qr2);
    });
  });

  describe('generateTOTPToken', () => {
    it('should generate a 6-digit token', () => {
      const secret = generateTOTPSecret();
      const token = generateTOTPToken(secret);

      expect(token).toMatch(/^\d{6}$/);
    });

    it('should throw on invalid base32 secret', () => {
      expect(() => generateTOTPToken('invalid!')).toThrow('Invalid base32 secret');
    });

    it('should throw on empty secret', () => {
      expect(() => generateTOTPToken('')).toThrow('Invalid base32 secret');
    });

    it('should generate consistent tokens for same secret in same time window', () => {
      const secret = generateTOTPSecret();
      const token1 = generateTOTPToken(secret);
      const token2 = generateTOTPToken(secret);

      expect(token1).toBe(token2);
    });
  });

  describe('getTOTPTimeRemaining', () => {
    it('should return a number between 1 and 30', () => {
      const remaining = getTOTPTimeRemaining();
      expect(remaining).toBeGreaterThanOrEqual(1);
      expect(remaining).toBeLessThanOrEqual(30);
    });
  });
});
