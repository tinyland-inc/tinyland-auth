/**
 * TOTP Service
 *
 * AES-256-GCM encrypted TOTP with timing-safe verification.
 *
 * @module @tinyland/auth/core/totp
 */
import type { TOTPSecret, EncryptedData, TOTPConfig } from '../../types/index.js';
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
export declare class TOTPService {
    private encryptionKey;
    private issuer;
    private devMode;
    private testCode?;
    constructor(config: TOTPServiceConfig);
    /**
     * Generate a new TOTP secret for a user
     */
    generateSecret(handle: string, email: string): Promise<TOTPSecret>;
    /**
     * Encrypt data using AES-256-GCM
     */
    encrypt(text: string): EncryptedData;
    /**
     * Decrypt data using AES-256-GCM
     */
    decrypt(encryptedData: EncryptedData): string;
    /**
     * Verify a TOTP token with timing attack prevention
     */
    verifyToken(secretOrNull: TOTPSecret | null, token: string): Promise<boolean>;
    /**
     * Generate a current TOTP token (for testing)
     */
    generateToken(secret: TOTPSecret): string;
    /**
     * Generate QR code URL from secret
     */
    generateQRCode(secret: TOTPSecret): Promise<string>;
    /**
     * Encrypt backup codes
     */
    encryptBackupCodes(codes: string[]): EncryptedData;
    /**
     * Decrypt backup codes
     */
    decryptBackupCodes(encryptedData: EncryptedData): string[];
}
/**
 * Create a TOTP service instance from config
 */
export declare function createTOTPService(config: TOTPConfig): TOTPService;
//# sourceMappingURL=index.d.ts.map