/**
 * TOTP Compatibility Layer
 *
 * Provides the old totp.ts API as standalone utility functions.
 * These are framework-agnostic and do not depend on $lib or singletons.
 *
 * @module @tummycrypt/tinyland-auth/totp/compat
 */

import { authenticator } from 'otplib';
import * as crypto from 'crypto';
import * as QRCode from 'qrcode';

// Configure authenticator settings
authenticator.options = {
  step: 30,
  window: 1,
  digits: 6,
};

/**
 * Generate a cryptographically secure TOTP secret
 * @returns Base32 encoded secret string
 */
export function generateTOTPSecret(): string {
  try {
    const secret = authenticator.generateSecret();
    return secret;
  } catch (_error) {
    throw new Error('Failed to generate secure TOTP secret');
  }
}

/**
 * Generate a TOTP URI for QR code generation
 * @param secret - Base32 encoded secret
 * @param issuer - Service name (e.g., "Tinyland.dev")
 * @param label - User identifier (e.g., email or username)
 * @returns otpauth:// URI string
 */
export function generateTOTPUri(secret: string, issuer: string, label: string): string {
  if (!secret || !issuer || !label) {
    throw new Error('Secret, issuer, and label are required');
  }

  // Validate secret is base32
  if (!/^[A-Z2-7]+=*$/i.test(secret)) {
    throw new Error('Invalid base32 secret');
  }

  // URL-encode the label and issuer for safety
  const encodedLabel = encodeURIComponent(label);
  const encodedIssuer = encodeURIComponent(issuer);

  // Build the URI manually for better compatibility
  const uri = `otpauth://totp/${encodedLabel}?secret=${secret}&issuer=${encodedIssuer}&algorithm=SHA1&digits=6&period=30`;

  return uri;
}

/**
 * Generate a secure temporary password
 * @param length - Password length (default: 8)
 * @returns Alphanumeric password string
 */
export function generateTempPassword(length: number = 8): string {
  if (length < 8) {
    throw new Error('Password must be at least 8 characters');
  }

  // Use a character set that's easy to read and type
  // Excludes ambiguous characters like 0, O, I, l
  const charset = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789';
  const charsetLength = charset.length;

  let password = '';

  // Generate password using crypto.randomInt for uniform distribution
  for (let i = 0; i < length; i++) {
    const randomIndex = crypto.randomInt(0, charsetLength);
    password += charset[randomIndex];
  }

  // Ensure password has at least one uppercase, lowercase, and digit
  const hasUpper = /[A-Z]/.test(password);
  const hasLower = /[a-z]/.test(password);
  const hasDigit = /[0-9]/.test(password);

  if (!hasUpper || !hasLower || !hasDigit) {
    // Recursively generate a new password if requirements aren't met
    return generateTempPassword(length);
  }

  return password;
}

/**
 * Generate a QR code data URL for TOTP setup
 * @param uri - The otpauth:// URI
 * @returns Promise<string> - Base64 encoded data URL
 */
export async function generateTOTPQRCode(uri: string): Promise<string> {
  try {
    // Generate QR code as data URL for secure display
    const qrCodeDataUrl = await QRCode.toDataURL(uri, {
      errorCorrectionLevel: 'M',
      margin: 4,
      width: 256,
      color: {
        dark: '#000000',
        light: '#FFFFFF',
      },
    });

    return qrCodeDataUrl;
  } catch (_error) {
    throw new Error('Failed to generate QR code');
  }
}

/**
 * Generate current TOTP token for a secret
 * @param secret - Base32 encoded secret
 * @returns Current 6-digit token
 */
export function generateTOTPToken(secret: string): string {
  if (!secret || !/^[A-Z2-7]+=*$/i.test(secret)) {
    throw new Error('Invalid base32 secret');
  }

  return authenticator.generate(secret);
}

/**
 * Get time remaining until current TOTP expires
 * @returns Number of seconds until token refresh
 */
export function getTOTPTimeRemaining(): number {
  const step = authenticator.options.step || 30;
  const now = Math.floor(Date.now() / 1000);
  return step - (now % step);
}
