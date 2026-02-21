/**
 * mTLS Certificate Validation
 *
 * Framework-agnostic mTLS certificate extraction and validation.
 * Takes raw header values as input instead of framework-specific request objects.
 *
 * @module @tinyland/auth/core/security/mtls
 */

import { createHash } from 'crypto';

/**
 * Raw certificate headers extracted from the HTTP request.
 * Common header names used by reverse proxies (nginx, envoy, Caddy).
 */
export interface CertificateHeaders {
  /** X-SSL-Client-Cert or X-Client-Cert or X-Forwarded-Client-Cert */
  clientCert?: string;
  /** X-SSL-Client-S-DN or X-Client-DN */
  clientSubject?: string;
  /** X-SSL-Client-Verify or X-Client-Verified */
  clientVerify?: string;
  /** X-SSL-Client-I-DN */
  clientIssuer?: string;
}

/**
 * Parsed certificate information
 */
export interface CertificateInfo {
  isValid: boolean;
  fingerprint?: string;
  subject?: string;
  issuer?: string;
  validFrom?: Date;
  validTo?: Date;
}

/**
 * Options for certificate extraction
 */
export interface MTLSOptions {
  /** Whether the application is running in development mode */
  isDevelopment: boolean;
  /** Optional set of valid certificate fingerprints for allowlist checking */
  validFingerprints?: Set<string>;
}

/**
 * Extract and validate a client certificate from HTTP headers.
 *
 * In development mode, returns a synthetic valid certificate.
 * In production, validates the certificate headers provided by the reverse proxy.
 *
 * @param headers - Certificate-related headers from the HTTP request
 * @param options - Extraction options including environment detection
 * @returns Parsed certificate information
 *
 * @example
 * ```typescript
 * const certInfo = extractCertificate(
 *   {
 *     clientCert: req.headers['x-ssl-client-cert'],
 *     clientSubject: req.headers['x-ssl-client-s-dn'],
 *     clientVerify: req.headers['x-ssl-client-verify'],
 *     clientIssuer: req.headers['x-ssl-client-i-dn'],
 *   },
 *   { isDevelopment: process.env.NODE_ENV === 'development' }
 * );
 * ```
 */
export function extractCertificate(
  headers: CertificateHeaders,
  options: MTLSOptions
): CertificateInfo {
  // In development, bypass certificate check entirely
  if (options.isDevelopment) {
    return {
      isValid: true,
      fingerprint: 'dev-mode-no-cert',
      subject: 'Development Mode',
      issuer: 'Local Development',
      validFrom: new Date(),
      validTo: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000),
    };
  }

  // Check if certificate verification passed
  if (
    headers.clientVerify &&
    headers.clientVerify !== 'SUCCESS' &&
    headers.clientVerify !== 'NONE'
  ) {
    return { isValid: false };
  }

  // If no certificate provided
  if (!headers.clientCert && !headers.clientSubject) {
    return { isValid: false };
  }

  // Calculate fingerprint if certificate is provided
  let fingerprint = '';
  if (headers.clientCert) {
    const cleanCert = decodeURIComponent(headers.clientCert)
      .replace(/\s+/g, '\n')
      .replace(/-----BEGIN\sCERTIFICATE-----/, '-----BEGIN CERTIFICATE-----')
      .replace(/-----END\sCERTIFICATE-----/, '-----END CERTIFICATE-----');

    fingerprint = 'sha256:' + createHash('sha256').update(cleanCert).digest('hex');
  }

  // Check against allowlist if provided
  const isValid = options.validFingerprints
    ? options.validFingerprints.has(fingerprint)
    : true;

  return {
    isValid,
    fingerprint,
    subject: headers.clientSubject || 'Unknown',
    issuer: headers.clientIssuer || 'Unknown',
    validFrom: new Date(),
    validTo: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000),
  };
}

/**
 * Get certificate fingerprint from headers.
 * Returns null if no valid certificate is present.
 */
export function getCertificateFingerprint(
  headers: CertificateHeaders,
  options: MTLSOptions
): string | null {
  const certInfo = extractCertificate(headers, options);
  return certInfo.isValid ? certInfo.fingerprint || null : null;
}
