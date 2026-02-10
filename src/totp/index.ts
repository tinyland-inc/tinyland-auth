/**
 * TOTP Sub-entry Point
 *
 * Re-exports the core TOTP service and compatibility layer utilities.
 *
 * @module @tinyland-inc/tinyland-auth/totp
 */

// Core TOTP service
export {
  TOTPService,
  createTOTPService,
  type TOTPServiceConfig,
} from '../core/totp/index.js';

// Compatibility layer utilities
export {
  generateTOTPSecret,
  generateTOTPUri,
  generateTempPassword,
  generateTOTPQRCode,
  generateTOTPToken,
  getTOTPTimeRemaining,
} from './compat.js';

// Types
export type { TOTPSecret, EncryptedData } from '../types/auth.js';
