/**
 * Password Hashing Utilities Tests
 */

import { describe, it, expect } from 'vitest';
import {
  hashPassword,
  verifyPassword,
  needsRehash,
  getHashRounds,
  generateSecurePassword,
} from '../src/core/security/password.js';

describe('Password Hashing', { timeout: 30_000 }, () => {
  describe('hashPassword', () => {
    it('should hash a password', async () => {
      const password = 'mySecurePassword123!';
      const hash = await hashPassword(password);

      expect(hash).toBeDefined();
      expect(hash).toMatch(/^\$2[aby]?\$\d+\$/);
      expect(hash).not.toBe(password);
    });

    it('should use default 12 rounds', async () => {
      const hash = await hashPassword('test');
      const rounds = getHashRounds(hash);
      expect(rounds).toBe(12);
    });

    it('should respect custom rounds', async () => {
      const hash = await hashPassword('test', { rounds: 10 });
      const rounds = getHashRounds(hash);
      expect(rounds).toBe(10);
    });

    it('should throw for invalid rounds', async () => {
      await expect(hashPassword('test', { rounds: 3 })).rejects.toThrow(
        'bcrypt rounds must be between 4 and 31'
      );
      await expect(hashPassword('test', { rounds: 32 })).rejects.toThrow(
        'bcrypt rounds must be between 4 and 31'
      );
    });

    it('should generate different hashes for same password', async () => {
      const password = 'samePassword';
      const hash1 = await hashPassword(password);
      const hash2 = await hashPassword(password);

      expect(hash1).not.toBe(hash2);
    });
  });

  describe('verifyPassword', () => {
    it('should verify correct password', async () => {
      const password = 'correctPassword123!';
      const hash = await hashPassword(password);

      const isValid = await verifyPassword(password, hash);
      expect(isValid).toBe(true);
    });

    it('should reject incorrect password', async () => {
      const password = 'correctPassword123!';
      const hash = await hashPassword(password);

      const isValid = await verifyPassword('wrongPassword', hash);
      expect(isValid).toBe(false);
    });

    it('should handle special characters', async () => {
      const password = '!@#$%^&*()_+-=[]{}|;:,.<>?';
      const hash = await hashPassword(password);

      expect(await verifyPassword(password, hash)).toBe(true);
      expect(await verifyPassword('different', hash)).toBe(false);
    });

    it('should handle unicode characters', async () => {
      const password = '密码123パスワードكلمة';
      const hash = await hashPassword(password);

      expect(await verifyPassword(password, hash)).toBe(true);
    });

    it('should handle empty password', async () => {
      const hash = await hashPassword('');
      expect(await verifyPassword('', hash)).toBe(true);
      expect(await verifyPassword('notEmpty', hash)).toBe(false);
    });
  });

  describe('needsRehash', () => {
    it('should return false when hash rounds match desired', async () => {
      const hash = await hashPassword('test', { rounds: 12 });
      expect(needsRehash(hash, 12)).toBe(false);
    });

    it('should return true when hash rounds are lower than desired', async () => {
      const hash = await hashPassword('test', { rounds: 10 });
      expect(needsRehash(hash, 12)).toBe(true);
    });

    it('should return false when hash rounds are higher than desired', async () => {
      const hash = await hashPassword('test', { rounds: 14 });
      expect(needsRehash(hash, 12)).toBe(false);
    });

    it('should return true for invalid hash format', () => {
      expect(needsRehash('invalid-hash', 12)).toBe(true);
      expect(needsRehash('', 12)).toBe(true);
    });
  });

  describe('getHashRounds', () => {
    it('should extract rounds from bcrypt hash', async () => {
      const hash10 = await hashPassword('test', { rounds: 10 });
      const hash12 = await hashPassword('test', { rounds: 12 });

      expect(getHashRounds(hash10)).toBe(10);
      expect(getHashRounds(hash12)).toBe(12);
    });

    it('should return null for invalid hash', () => {
      expect(getHashRounds('invalid')).toBeNull();
      expect(getHashRounds('')).toBeNull();
    });
  });

  describe('generateSecurePassword', () => {
    it('should generate password of specified length', () => {
      const pwd16 = generateSecurePassword(16);
      const pwd32 = generateSecurePassword(32);

      expect(pwd16.length).toBe(16);
      expect(pwd32.length).toBe(32);
    });

    it('should generate different passwords each time', () => {
      const passwords = Array.from({ length: 10 }, () => generateSecurePassword(16));
      const unique = new Set(passwords);
      expect(unique.size).toBe(10);
    });

    it('should respect character options', () => {
      const numbersOnly = generateSecurePassword(20, {
        includeUppercase: false,
        includeLowercase: false,
        includeNumbers: true,
        includeSpecial: false,
      });
      expect(numbersOnly).toMatch(/^[0-9]+$/);

      const lettersOnly = generateSecurePassword(20, {
        includeUppercase: true,
        includeLowercase: true,
        includeNumbers: false,
        includeSpecial: false,
      });
      expect(lettersOnly).toMatch(/^[a-zA-Z]+$/);
    });

    it('should use default charset when all options false', () => {
      const pwd = generateSecurePassword(16, {
        includeUppercase: false,
        includeLowercase: false,
        includeNumbers: false,
        includeSpecial: false,
      });
      expect(pwd.length).toBe(16);
      expect(pwd).toMatch(/^[a-z0-9]+$/);
    });
  });
});
