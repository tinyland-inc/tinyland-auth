








import { createHash } from 'crypto';





export interface CertificateHeaders {
  
  clientCert?: string;
  
  clientSubject?: string;
  
  clientVerify?: string;
  
  clientIssuer?: string;
}




export interface CertificateInfo {
  isValid: boolean;
  fingerprint?: string;
  subject?: string;
  issuer?: string;
  validFrom?: Date;
  validTo?: Date;
}




export interface MTLSOptions {
  
  isDevelopment: boolean;
  
  validFingerprints?: Set<string>;
}
























export function extractCertificate(
  headers: CertificateHeaders,
  options: MTLSOptions
): CertificateInfo {
  
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

  
  if (
    headers.clientVerify &&
    headers.clientVerify !== 'SUCCESS' &&
    headers.clientVerify !== 'NONE'
  ) {
    return { isValid: false };
  }

  
  if (!headers.clientCert && !headers.clientSubject) {
    return { isValid: false };
  }

  
  let fingerprint = '';
  if (headers.clientCert) {
    const cleanCert = decodeURIComponent(headers.clientCert)
      .replace(/\s+/g, '\n')
      .replace(/-----BEGIN\sCERTIFICATE-----/, '-----BEGIN CERTIFICATE-----')
      .replace(/-----END\sCERTIFICATE-----/, '-----END CERTIFICATE-----');

    fingerprint = 'sha256:' + createHash('sha256').update(cleanCert).digest('hex');
  }

  
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





export function getCertificateFingerprint(
  headers: CertificateHeaders,
  options: MTLSOptions
): string | null {
  const certInfo = extractCertificate(headers, options);
  return certInfo.isValid ? certInfo.fingerprint || null : null;
}
