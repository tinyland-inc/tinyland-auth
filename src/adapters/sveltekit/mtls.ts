







import type { RequestEvent } from '@sveltejs/kit';
import {
  extractCertificate as coreExtractCertificate,
  getCertificateFingerprint as coreGetCertificateFingerprint,
  type CertificateHeaders,
  type CertificateInfo,
  type MTLSOptions,
} from '../../core/security/mtls.js';


export type { CertificateHeaders, CertificateInfo, MTLSOptions };




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




function detectDevelopment(event: RequestEvent): boolean {
  return (
    process.env.NODE_ENV === 'development' ||
    !process.env.NODE_ENV ||
    event.url.hostname === 'localhost' ||
    event.url.hostname === '127.0.0.1' ||
    event.url.hostname.endsWith('.local')
  );
}




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






export function requireMTLS(event: RequestEvent): boolean {
  const certInfo = extractCertificateFromEvent(event);

  if (!certInfo.isValid) {
    return false;
  }

  (event.locals as unknown as { mTLSCert: CertificateInfo }).mTLSCert = certInfo;
  return true;
}




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
