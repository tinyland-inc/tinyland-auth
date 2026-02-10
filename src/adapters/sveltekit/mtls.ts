/**
 * SvelteKit mTLS Adapter
 *
 * Wraps the core mTLS functions to extract headers from SvelteKit RequestEvent.
 *
 * @module @tinyland/auth/sveltekit
 */

import type { RequestEvent } from '@sveltejs/kit';
import {
  extractCertificate as coreExtractCertificate,
  getCertificateFingerprint as coreGetCertificateFingerprint,
  type CertificateHeaders,
  type CertificateInfo,
  type MTLSOptions,
} from '../../core/security/mtls.js';

// Re-export core types
export type { CertificateHeaders, CertificateInfo, MTLSOptions };

/**
 * Extract headers relevant to mTLS from a SvelteKit RequestEvent.
 */
function extractHeadersFromEvent(event: RequestEvent): CertificateHeaders {
  return {
    clientCert:
      event.request.headers.get('X-SSL-Client-Cert') ||
      event.request.headers.get('X-Client-Cert') ||
      event.request.headers.get('X-Forwarded-Client-Cert') ||
      undefined,
    clientSubject:
      event.request.headers.get('X-SSL-Client-S-DN') ||
      event.request.headers.get('X-Client-DN') ||
      undefined,
    clientVerify:
      event.request.headers.get('X-SSL-Client-Verify') ||
      event.request.headers.get('X-Client-Verified') ||
      undefined,
    clientIssuer: event.request.headers.get('X-SSL-Client-I-DN') || undefined,
  };
}

/**
 * Detect if running in development mode from the SvelteKit event.
 */
function detectDevelopment(event: RequestEvent): boolean {
  return (
    process.env.NODE_ENV === 'development' ||
    !process.env.NODE_ENV ||
    event.url.hostname === 'localhost' ||
    event.url.hostname === '127.0.0.1' ||
    event.url.hostname.endsWith('.local')
  );
}

/**
 * Extract certificate from SvelteKit RequestEvent.
 */
export function extractCertificateFromEvent(
  event: RequestEvent,
  options?: Partial<MTLSOptions>
): CertificateInfo {
  const headers = extractHeadersFromEvent(event);
  const isDevelopment = options?.isDevelopment ?? detectDevelopment(event);
  return coreExtractCertificate(headers, {
    isDevelopment,
    validFingerprints: options?.validFingerprints,
  });
}

/**
 * SvelteKit middleware to check mTLS certificate.
 * Returns true if certificate is valid, false otherwise.
 * Stores certificate info in event.locals.mTLSCert.
 */
export function requireMTLS(event: RequestEvent): boolean {
  const certInfo = extractCertificateFromEvent(event);

  if (!certInfo.isValid) {
    return false;
  }

  (event.locals as unknown as { mTLSCert: CertificateInfo }).mTLSCert = certInfo;
  return true;
}

/**
 * Get certificate fingerprint from SvelteKit RequestEvent.
 */
export function getCertificateFingerprintFromEvent(
  event: RequestEvent,
  options?: Partial<MTLSOptions>
): string | null {
  const headers = extractHeadersFromEvent(event);
  const isDevelopment = options?.isDevelopment ?? detectDevelopment(event);
  return coreGetCertificateFingerprint(headers, {
    isDevelopment,
    validFingerprints: options?.validFingerprints,
  });
}
