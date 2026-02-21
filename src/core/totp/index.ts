/**
 * TOTP Service
 *
 * AES-256-GCM encrypted TOTP with timing-safe verification.
 *
 * @module @tinyland/auth/core/totp
 */

import { authenticator } from 'otplib';
import * as qrcode from 'qrcode';
import { createCipheriv, createDecipheriv, randomBytes, scryptSync } from 'crypto';
import type { TOTPSecret, EncryptedData, TOTPConfig } from '../../types/index.js';
import { timingSafeVerify } from '../security/index.js';

// Configure authenticator with time window for clock drift tolerance
authenticator.options = { window: 1 };

// Encryption constants
const ALGORITHM = 'aes-256-gcm';
const SALT_LENGTH = 32;
const IV_LENGTH = 16;
const KEY_LENGTH = 32;

export interface TOTPServiceConfig {
  /** Encryption key for TOTP secrets */
  encryptionKey: string;
  /** Issuer name for authenticator apps */
  issuer: string;
  /** Development mode (allows test codes) */
  devMode?: boolean;
  /** Test code for development */
  testCode?: string;
}

export class TOTPService {
  private encryptionKey: string;
  private issuer: string;
  private devMode: boolean;
  private testCode?: string;

  constructor(config: TOTPServiceConfig) {
    this.encryptionKey = config.encryptionKey;
    this.issuer = config.issuer;
    this.devMode = config.devMode || false;
    this.testCode = config.testCode;
  }

  /**
   * Generate a new TOTP secret for a user
   */
  async generateSecret(handle: string, email: string): Promise<TOTPSecret> {
    const secret = authenticator.generateSecret();
    const otpauth = authenticator.keyuri(email, this.issuer, secret);
    const qrCodeUrl = await qrcode.toDataURL(otpauth);

    return {
      handle,
      email,
      secret,
      qrCodeUrl,
      createdAt: new Date(),
    };
  }

  /**
   * Encrypt data using AES-256-GCM
   */
  encrypt(text: string): EncryptedData {
    const salt = randomBytes(SALT_LENGTH);
    const key = scryptSync(this.encryptionKey, salt, KEY_LENGTH);
    const iv = randomBytes(IV_LENGTH);
    const cipher = createCipheriv(ALGORITHM, key, iv);

    const encrypted = Buffer.concat([
      cipher.update(text, 'utf8'),
      cipher.final(),
    ]);

    const tag = cipher.getAuthTag();

    return {
      encrypted: encrypted.toString('base64'),
      salt: salt.toString('base64'),
      iv: iv.toString('base64'),
      tag: tag.toString('base64'),
    };
  }

  /**
   * Decrypt data using AES-256-GCM
   */
  decrypt(encryptedData: EncryptedData): string {
    const salt = Buffer.from(encryptedData.salt, 'base64');
    const key = scryptSync(this.encryptionKey, salt, KEY_LENGTH);
    const iv = Buffer.from(encryptedData.iv, 'base64');
    const tag = Buffer.from(encryptedData.tag, 'base64');
    const encrypted = Buffer.from(encryptedData.encrypted, 'base64');

    const decipher = createDecipheriv(ALGORITHM, key, iv);
    decipher.setAuthTag(tag);

    const decrypted = Buffer.concat([
      decipher.update(encrypted),
      decipher.final(),
    ]);

    return decrypted.toString('utf8');
  }

  /**
   * Verify a TOTP token with timing attack prevention
   */
  async verifyToken(
    secretOrNull: TOTPSecret | null,
    token: string
  ): Promise<boolean> {
    const cleanToken = token.replace(/\s/g, '');

    // Check test code in dev mode
    if (this.devMode && this.testCode && cleanToken === this.testCode) {
      return true;
    }

    return await timingSafeVerify(async () => {
      if (!secretOrNull) {
        // Perform dummy verification to maintain timing
        const dummySecret = 'JBSWY3DPEHPK3PXP';
        authenticator.verify({ token: cleanToken, secret: dummySecret });
        return false;
      }

      return authenticator.verify({
        token: cleanToken,
        secret: secretOrNull.secret,
      });
    }, 150);
  }

  /**
   * Generate a current TOTP token (for testing)
   */
  generateToken(secret: TOTPSecret): string {
    return authenticator.generate(secret.secret);
  }

  /**
   * Generate QR code URL from secret
   */
  async generateQRCode(secret: TOTPSecret): Promise<string> {
    const otpauth = authenticator.keyuri(secret.email, this.issuer, secret.secret);
    return await qrcode.toDataURL(otpauth);
  }

  /**
   * Encrypt backup codes
   */
  encryptBackupCodes(codes: string[]): EncryptedData {
    return this.encrypt(JSON.stringify(codes));
  }

  /**
   * Decrypt backup codes
   */
  decryptBackupCodes(encryptedData: EncryptedData): string[] {
    const json = this.decrypt(encryptedData);
    return JSON.parse(json);
  }
}

/**
 * Create a TOTP service instance from config
 */
export function createTOTPService(config: TOTPConfig): TOTPService {
  return new TOTPService({
    encryptionKey: config.encryptionKey,
    issuer: config.issuer,
    devMode: config.devMode,
  });
}
