/**
 * Validation Sub-entry Point
 *
 * Handle validation, mTLS certificate checking, and other validators.
 *
 * @module @tummycrypt/tinyland-auth/validation
 */

// Handle validation
export {
  validateHandle,
  addHandle,
  removeHandle,
  listHandles,
  type HandleValidatorConfig,
  type HandleValidationResult,
} from './handle-validator.js';

// mTLS certificate validation (re-exported from core/security)
export {
  extractCertificate,
  getCertificateFingerprint,
  type CertificateHeaders,
  type CertificateInfo,
  type MTLSOptions,
} from '../core/security/mtls.js';
