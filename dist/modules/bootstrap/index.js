/**
 * Bootstrap Module
 *
 * Handles first-time system setup and super_admin creation.
 * The bootstrap flow ensures the first user has TOTP enabled
 * and backup codes generated before completing setup.
 *
 * @module @tinyland/auth/modules/bootstrap
 */
import { hashPassword } from '../../core/security/password.js';
import { generateBackupCodes, createBackupCodeSet } from '../../core/backup-codes/index.js';
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
export class BootstrapService {
    config;
    constructor(config) {
        this.config = {
            ...config,
            bcryptRounds: config.bcryptRounds ?? 12,
            backupCodesCount: config.backupCodesCount ?? 10,
        };
    }
    /**
     * Check bootstrap status
     */
    async getStatus() {
        const hasUsers = await this.config.storage.hasUsers();
        return {
            needsBootstrap: !hasUsers,
            hasUsers,
            systemConfigured: hasUsers,
        };
    }
    /**
     * Initialize bootstrap flow (step 1)
     *
     * Creates credentials and generates TOTP secret.
     * Returns state to be stored in session for subsequent steps.
     */
    async initiate(request) {
        // Verify bootstrap is allowed
        const status = await this.getStatus();
        if (!status.needsBootstrap) {
            throw new Error('Bootstrap not allowed: users already exist');
        }
        // Validate handle format
        if (!/^[a-zA-Z][a-zA-Z0-9_-]{2,29}$/.test(request.handle)) {
            throw new Error('Handle must start with a letter, be 3-30 characters, and contain only letters, numbers, underscores, or hyphens');
        }
        // Hash password
        const passwordHash = await hashPassword(request.password, {
            rounds: this.config.bcryptRounds,
        });
        // Generate TOTP secret
        const totpSecret = this.config.generateTOTPSecret();
        // Generate QR code
        const qrCodeUrl = await this.config.generateQRCode(request.handle, totpSecret, this.config.appName);
        // Generate backup codes
        const backupCodes = generateBackupCodes(this.config.backupCodesCount);
        // Create state for session storage
        const state = {
            handle: request.handle,
            passwordHash,
            displayName: request.displayName,
            email: request.email,
            totpSecret,
            backupCodes,
            timestamp: Date.now(),
            step: 1,
        };
        return {
            state,
            qrCodeUrl,
            backupCodes,
        };
    }
    /**
     * Update profile during bootstrap (step 2)
     */
    updateProfile(state, profile) {
        return {
            ...state,
            profile,
            step: 2,
        };
    }
    /**
     * Verify TOTP and complete bootstrap (final step)
     */
    async complete(state, verification) {
        // Validate state
        if (!state || !state.handle || !state.totpSecret) {
            return {
                success: false,
                error: 'Invalid bootstrap state',
            };
        }
        // Check state hasn't expired (10 minutes)
        const maxAge = 10 * 60 * 1000;
        if (Date.now() - state.timestamp > maxAge) {
            return {
                success: false,
                error: 'Bootstrap session expired. Please start over.',
            };
        }
        // Verify handle matches
        if (state.handle !== verification.handle) {
            return {
                success: false,
                error: 'Handle mismatch',
            };
        }
        // Verify TOTP code
        const isValidTOTP = this.config.verifyTOTP(state.totpSecret, verification.totpCode);
        if (!isValidTOTP) {
            return {
                success: false,
                error: 'Invalid TOTP code. Please check your authenticator app.',
            };
        }
        try {
            // Encrypt and save TOTP secret FIRST
            const encryptedSecret = await this.config.encryptTOTPSecret(state.handle, state.totpSecret);
            await this.config.storage.saveTOTPSecret(state.handle, encryptedSecret);
            // Verify it was saved
            const savedSecret = await this.config.storage.getTOTPSecret(state.handle);
            if (!savedSecret) {
                throw new Error('Failed to verify TOTP secret was saved');
            }
            // Create backup code set
            const backupCodeSet = createBackupCodeSet('pending', // Will be updated with user ID
            state.backupCodes);
            // Create user
            const user = await this.config.storage.createUser({
                handle: state.handle,
                email: state.email || `${state.handle}@localhost`,
                displayName: state.displayName,
                passwordHash: state.passwordHash,
                role: 'super_admin',
                isActive: true,
                totpEnabled: true,
                totpSecretId: state.handle,
                needsOnboarding: false,
                onboardingStep: 0,
                createdAt: new Date().toISOString(),
                updatedAt: new Date().toISOString(),
                bio: state.profile?.bio,
                pronouns: state.profile?.pronouns,
                avatarUrl: state.profile?.avatarUrl,
            });
            // Update backup codes with actual user ID
            backupCodeSet.userId = user.id;
            await this.config.storage.saveBackupCodes(user.id, backupCodeSet);
            // Log audit event
            await this.config.storage.logAuditEvent({
                timestamp: new Date().toISOString(),
                type: 'BOOTSTRAP_COMPLETED',
                userId: user.id,
                handle: user.handle,
                details: {
                    role: 'super_admin',
                    totpEnabled: true,
                    backupCodesGenerated: state.backupCodes.length,
                },
                severity: 'info',
                source: 'system',
            });
            // Return success (without sensitive data)
            const safeUser = {
                ...user,
            };
            delete safeUser.passwordHash;
            return {
                success: true,
                user: safeUser,
                backupCodes: state.backupCodes,
            };
        }
        catch (error) {
            return {
                success: false,
                error: error instanceof Error ? error.message : 'Bootstrap failed',
            };
        }
    }
    /**
     * Validate bootstrap state hasn't expired
     */
    isStateValid(state, maxAgeMs = 600000) {
        if (!state || !state.timestamp) {
            return false;
        }
        return Date.now() - state.timestamp < maxAgeMs;
    }
}
/**
 * Create a bootstrap service instance
 */
export function createBootstrapService(config) {
    return new BootstrapService(config);
}
//# sourceMappingURL=index.js.map