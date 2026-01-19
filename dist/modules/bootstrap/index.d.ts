/**
 * Bootstrap Module
 *
 * Handles first-time system setup and super_admin creation.
 * The bootstrap flow ensures the first user has TOTP enabled
 * and backup codes generated before completing setup.
 *
 * @module @tinyland/auth/modules/bootstrap
 */
import type { IStorageAdapter } from '../../storage/interface.js';
import type { EncryptedTOTPSecret } from '../../types/auth.js';
import type { BootstrapRequest, BootstrapResponse, BootstrapVerificationRequest, BootstrapStatus } from '../../types/api.js';
/**
 * Bootstrap service configuration
 */
export interface BootstrapServiceConfig {
    /** Storage adapter for persistence */
    storage: IStorageAdapter;
    /** Application name for TOTP issuer */
    appName: string;
    /** bcrypt rounds for password hashing */
    bcryptRounds: number;
    /** Number of backup codes to generate */
    backupCodesCount: number;
    /** TOTP secret generator function */
    generateTOTPSecret: () => string;
    /** TOTP QR code generator function */
    generateQRCode: (handle: string, secret: string, issuer: string) => Promise<string>;
    /** TOTP verification function */
    verifyTOTP: (secret: string, token: string) => boolean;
    /** TOTP secret encryption function */
    encryptTOTPSecret: (handle: string, secret: string) => Promise<EncryptedTOTPSecret>;
}
/**
 * Bootstrap state stored in session/cookie during multi-step flow
 */
export interface BootstrapState {
    handle: string;
    passwordHash: string;
    displayName: string;
    email?: string;
    totpSecret: string;
    backupCodes: string[];
    timestamp: number;
    step: number;
    profile?: {
        bio?: string;
        pronouns?: string;
        avatarUrl?: string;
    };
}
/**
 * Bootstrap Service
 *
 * Manages the initial system setup flow:
 * 1. Check if bootstrap is needed (no users exist)
 * 2. Create first super_admin with credentials
 * 3. Set up TOTP and generate QR code
 * 4. Generate and store backup codes
 * 5. Verify TOTP before finalizing
 *
 * @example
 * ```typescript
 * import { BootstrapService } from '@tinyland/auth/modules/bootstrap';
 *
 * const bootstrap = new BootstrapService({
 *   storage,
 *   appName: 'My App',
 *   generateTOTPSecret: () => authenticator.generateSecret(),
 *   generateQRCode: async (handle, secret, issuer) => {
 *     const uri = authenticator.keyuri(handle, issuer, secret);
 *     return qrcode.toDataURL(uri);
 *   },
 *   verifyTOTP: (secret, token) => authenticator.verify({ token, secret }),
 *   encryptTOTPSecret: async (handle, secret) => totpService.encrypt(handle, secret),
 * });
 *
 * // Check status
 * const status = await bootstrap.getStatus();
 * if (status.needsBootstrap) {
 *   // Start bootstrap flow
 * }
 * ```
 */
export declare class BootstrapService {
    private config;
    constructor(config: BootstrapServiceConfig);
    /**
     * Check bootstrap status
     */
    getStatus(): Promise<BootstrapStatus>;
    /**
     * Initialize bootstrap flow (step 1)
     *
     * Creates credentials and generates TOTP secret.
     * Returns state to be stored in session for subsequent steps.
     */
    initiate(request: BootstrapRequest): Promise<{
        state: BootstrapState;
        qrCodeUrl: string;
        backupCodes: string[];
    }>;
    /**
     * Update profile during bootstrap (step 2)
     */
    updateProfile(state: BootstrapState, profile: {
        bio?: string;
        pronouns?: string;
        avatarUrl?: string;
    }): BootstrapState;
    /**
     * Verify TOTP and complete bootstrap (final step)
     */
    complete(state: BootstrapState, verification: BootstrapVerificationRequest): Promise<BootstrapResponse>;
    /**
     * Validate bootstrap state hasn't expired
     */
    isStateValid(state: BootstrapState, maxAgeMs?: number): boolean;
}
/**
 * Create a bootstrap service instance
 */
export declare function createBootstrapService(config: BootstrapServiceConfig): BootstrapService;
export type { BootstrapRequest, BootstrapResponse, BootstrapVerificationRequest, BootstrapStatus };
//# sourceMappingURL=index.d.ts.map