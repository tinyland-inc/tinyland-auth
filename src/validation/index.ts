








export {
  validateHandle,
  addHandle,
  removeHandle,
  listHandles,
  type HandleValidatorConfig,
  type HandleValidationResult,
} from './handle-validator.js';


export {
  extractCertificate,
  getCertificateFingerprint,
  type CertificateHeaders,
  type CertificateInfo,
  type MTLSOptions,
} from '../core/security/mtls.js';
