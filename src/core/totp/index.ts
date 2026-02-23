







import { authenticator } from 'otplib';
import * as qrcode from 'qrcode';
import { createCipheriv, createDecipheriv, randomBytes, scryptSync } from 'crypto';
import type { TOTPSecret, EncryptedData, TOTPConfig } from '../../types/index.js';
import { timingSafeVerify } from '../security/index.js';


authenticator.options = { window: 1 };


const ALGORITHM = 'aes-256-gcm';
const SALT_LENGTH = 32;
const IV_LENGTH = 16;
const KEY_LENGTH = 32;

export interface TOTPServiceConfig {
  
  encryptionKey: string;
  
  issuer: string;
  
  devMode?: boolean;
  
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

  


  async verifyToken(
    secretOrNull: TOTPSecret | null,
    token: string
  ): Promise<boolean> {
    const cleanToken = token.replace(/\s/g, '');

    
    if (this.devMode && this.testCode && cleanToken === this.testCode) {
      return true;
    }

    return await timingSafeVerify(async () => {
      if (!secretOrNull) {
        
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

  


  generateToken(secret: TOTPSecret): string {
    return authenticator.generate(secret.secret);
  }

  


  async generateQRCode(secret: TOTPSecret): Promise<string> {
    const otpauth = authenticator.keyuri(secret.email, this.issuer, secret.secret);
    return await qrcode.toDataURL(otpauth);
  }

  


  encryptBackupCodes(codes: string[]): EncryptedData {
    return this.encrypt(JSON.stringify(codes));
  }

  


  decryptBackupCodes(encryptedData: EncryptedData): string[] {
    const json = this.decrypt(encryptedData);
    return JSON.parse(json);
  }
}




export function createTOTPService(config: TOTPConfig): TOTPService {
  return new TOTPService({
    encryptionKey: config.encryptionKey,
    issuer: config.issuer,
    devMode: config.devMode,
  });
}
