/**
 * Credentials Module Unit Tests
 *
 * Tests for credential generation, text card creation, and helper functions.
 */

import { describe, it, expect } from 'vitest';
import {
  generateTextCredentialsCard,
  maskPassword,
  escapeXml,
} from '../src/credentials/generator.js';
import {
  generateUserCredentials,
  generateCredentialsEmailHtml,
  generateSecureCredentialsLink,
  createCredentialsDownloadResponse,
} from '../src/credentials/helpers.js';

describe('Credentials Generator', () => {
  describe('generateTextCredentialsCard', () => {
    it('should include username and display name', () => {
      const card = generateTextCredentialsCard({
        username: 'testuser',
        displayName: 'Test User',
        tempPassword: 'TempPass123',
        totpUri: 'otpauth://totp/test?secret=JBSWY3DPEHPK3PXP',
      });

      expect(card).toContain('testuser');
      expect(card).toContain('Test User');
    });

    it('should include masked password', () => {
      const card = generateTextCredentialsCard({
        username: 'testuser',
        displayName: 'Test User',
        tempPassword: 'SecretPassword',
        totpUri: 'otpauth://totp/test?secret=JBSWY3DPEHPK3PXP',
      });

      // Should not contain the actual password
      expect(card).not.toContain('SecretPassword');
      // Should contain the masked version
      expect(card).toContain('Se**********rd');
    });

    it('should include TOTP URI', () => {
      const uri = 'otpauth://totp/test?secret=JBSWY3DPEHPK3PXP';
      const card = generateTextCredentialsCard({
        username: 'testuser',
        displayName: 'Test User',
        tempPassword: 'TempPass123',
        totpUri: uri,
      });

      expect(card).toContain(uri);
    });

    it('should include setup instructions', () => {
      const card = generateTextCredentialsCard({
        username: 'testuser',
        displayName: 'Test User',
        tempPassword: 'TempPass123',
        totpUri: 'otpauth://totp/test?secret=JBSWY3DPEHPK3PXP',
      });

      expect(card).toContain('Setup Instructions');
      expect(card).toContain('authenticator app');
    });

    it('should include security warning', () => {
      const card = generateTextCredentialsCard({
        username: 'testuser',
        displayName: 'Test User',
        tempPassword: 'TempPass123',
        totpUri: 'otpauth://totp/test?secret=JBSWY3DPEHPK3PXP',
      });

      expect(card).toContain('SECURITY WARNING');
    });

    it('should use custom issuer when provided', () => {
      const card = generateTextCredentialsCard({
        username: 'testuser',
        displayName: 'Test User',
        tempPassword: 'TempPass123',
        totpUri: 'otpauth://totp/test?secret=JBSWY3DPEHPK3PXP',
        issuer: 'Custom App',
      });

      expect(card).toContain('Custom App');
    });
  });

  describe('maskPassword', () => {
    it('should mask middle characters of password', () => {
      expect(maskPassword('SecretPassword')).toBe('Se**********rd');
    });

    it('should return dashes for very short passwords', () => {
      expect(maskPassword('abc')).toBe('--------');
      expect(maskPassword('ab')).toBe('--------');
    });

    it('should handle exactly 4 character passwords', () => {
      expect(maskPassword('abcd')).toBe('--------');
    });

    it('should handle 5 character passwords', () => {
      expect(maskPassword('abcde')).toBe('ab*de');
    });

    it('should show first 2 and last 2 characters', () => {
      const masked = maskPassword('HelloWorld');
      expect(masked.startsWith('He')).toBe(true);
      expect(masked.endsWith('ld')).toBe(true);
    });
  });

  describe('escapeXml', () => {
    it('should escape ampersands', () => {
      expect(escapeXml('a&b')).toBe('a&amp;b');
    });

    it('should escape angle brackets', () => {
      expect(escapeXml('<script>')).toBe('&lt;script&gt;');
    });

    it('should escape quotes', () => {
      expect(escapeXml('"hello"')).toBe('&quot;hello&quot;');
    });

    it('should escape apostrophes', () => {
      expect(escapeXml("it's")).toBe("it&apos;s");
    });

    it('should handle strings with no special characters', () => {
      expect(escapeXml('hello world')).toBe('hello world');
    });

    it('should handle empty string', () => {
      expect(escapeXml('')).toBe('');
    });
  });
});

describe('Credentials Helpers', () => {
  describe('generateUserCredentials', () => {
    it('should generate complete user credentials', async () => {
      const creds = await generateUserCredentials(
        'testuser',
        'Test User',
        'test@example.com'
      );

      expect(creds.username).toBe('testuser');
      expect(creds.displayName).toBe('Test User');
      expect(creds.email).toBe('test@example.com');
      expect(creds.tempPassword).toBeTruthy();
      expect(creds.totpSecret).toBeTruthy();
      expect(creds.credentialsText).toBeTruthy();
    });

    it('should generate a temp password of length 12', async () => {
      const creds = await generateUserCredentials(
        'testuser',
        'Test User',
        'test@example.com'
      );

      expect(creds.tempPassword!.length).toBe(12);
    });

    it('should generate a valid TOTP secret', async () => {
      const creds = await generateUserCredentials(
        'testuser',
        'Test User',
        'test@example.com'
      );

      expect(creds.totpSecret).toMatch(/^[A-Z2-7]+$/);
    });

    it('should include credentials text with user info', async () => {
      const creds = await generateUserCredentials(
        'testuser',
        'Test User',
        'test@example.com'
      );

      expect(creds.credentialsText).toContain('testuser');
      expect(creds.credentialsText).toContain('Test User');
    });
  });

  describe('createCredentialsDownloadResponse', () => {
    it('should create a Response with correct content type', () => {
      const response = createCredentialsDownloadResponse('test content', 'testuser');

      expect(response.headers.get('Content-Type')).toBe('text/plain');
    });

    it('should set content-disposition for download', () => {
      const response = createCredentialsDownloadResponse('test content', 'testuser');
      const disposition = response.headers.get('Content-Disposition');

      expect(disposition).toContain('attachment');
      expect(disposition).toContain('credentials-testuser-');
    });

    it('should set no-cache headers', () => {
      const response = createCredentialsDownloadResponse('test content', 'testuser');

      expect(response.headers.get('Cache-Control')).toContain('no-store');
      expect(response.headers.get('Pragma')).toBe('no-cache');
    });
  });

  describe('generateCredentialsEmailHtml', () => {
    it('should generate valid HTML', () => {
      const html = generateCredentialsEmailHtml({
        username: 'testuser',
        displayName: 'Test User',
        email: 'test@example.com',
        tempPassword: 'TempPass123',
      });

      expect(html).toContain('<!DOCTYPE html>');
      expect(html).toContain('</html>');
    });

    it('should include user information', () => {
      const html = generateCredentialsEmailHtml({
        username: 'testuser',
        displayName: 'Test User',
        email: 'test@example.com',
        tempPassword: 'TempPass123',
      });

      expect(html).toContain('testuser');
      expect(html).toContain('Test User');
      expect(html).toContain('test@example.com');
    });

    it('should mask the password', () => {
      const html = generateCredentialsEmailHtml({
        username: 'testuser',
        displayName: 'Test User',
        email: 'test@example.com',
        tempPassword: 'SecretPassword',
      });

      expect(html).not.toContain('SecretPassword');
    });

    it('should include setup instructions', () => {
      const html = generateCredentialsEmailHtml({
        username: 'testuser',
        displayName: 'Test User',
        email: 'test@example.com',
      });

      expect(html).toContain('Setup Instructions');
      expect(html).toContain('authenticator app');
    });
  });

  describe('generateSecureCredentialsLink', () => {
    it('should generate a URL with token', () => {
      const result = generateSecureCredentialsLink('test-id');

      expect(result.url).toContain('/admin/credentials/download/');
      expect(result.url.length).toBeGreaterThan(30);
    });

    it('should set expiry in the future', () => {
      const result = generateSecureCredentialsLink('test-id', 60);

      expect(result.expiresAt.getTime()).toBeGreaterThan(Date.now());
    });

    it('should respect custom expiry time', () => {
      const beforeMs = Date.now();
      const result = generateSecureCredentialsLink('test-id', 120);
      const afterMs = Date.now();

      // Should expire ~120 minutes from now
      const expectedMinMs = beforeMs + 120 * 60 * 1000;
      const expectedMaxMs = afterMs + 120 * 60 * 1000;

      expect(result.expiresAt.getTime()).toBeGreaterThanOrEqual(expectedMinMs);
      expect(result.expiresAt.getTime()).toBeLessThanOrEqual(expectedMaxMs);
    });

    it('should encode credentials ID in the token', () => {
      const result = generateSecureCredentialsLink('my-cred-id');
      const token = result.url.split('/').pop()!;
      const decoded = JSON.parse(Buffer.from(token, 'base64url').toString());

      expect(decoded.id).toBe('my-cred-id');
    });
  });
});
