








import { authenticator } from 'otplib';
import * as crypto from 'crypto';
import * as QRCode from 'qrcode';


authenticator.options = {
  step: 30,
  window: 1,
  digits: 6,
};





export function generateTOTPSecret(): string {
  try {
    const secret = authenticator.generateSecret();
    return secret;
  } catch (_error) {
    throw new Error('Failed to generate secure TOTP secret');
  }
}








export function generateTOTPUri(secret: string, issuer: string, label: string): string {
  if (!secret || !issuer || !label) {
    throw new Error('Secret, issuer, and label are required');
  }

  
  if (!/^[A-Z2-7]+=*$/i.test(secret)) {
    throw new Error('Invalid base32 secret');
  }

  
  const encodedLabel = encodeURIComponent(label);
  const encodedIssuer = encodeURIComponent(issuer);

  
  const uri = `otpauth://totp/${encodedLabel}?secret=${secret}&issuer=${encodedIssuer}&algorithm=SHA1&digits=6&period=30`;

  return uri;
}






export function generateTempPassword(length: number = 8): string {
  if (length < 8) {
    throw new Error('Password must be at least 8 characters');
  }

  
  
  const charset = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789';
  const charsetLength = charset.length;

  let password = '';

  
  for (let i = 0; i < length; i++) {
    const randomIndex = crypto.randomInt(0, charsetLength);
    password += charset[randomIndex];
  }

  
  const hasUpper = /[A-Z]/.test(password);
  const hasLower = /[a-z]/.test(password);
  const hasDigit = /[0-9]/.test(password);

  if (!hasUpper || !hasLower || !hasDigit) {
    
    return generateTempPassword(length);
  }

  return password;
}






export async function generateTOTPQRCode(uri: string): Promise<string> {
  try {
    
    const qrCodeDataUrl = await QRCode.toDataURL(uri, {
      errorCorrectionLevel: 'M',
      margin: 4,
      width: 256,
      color: {
        dark: '#000000',
        light: '#FFFFFF',
      },
    });

    return qrCodeDataUrl;
  } catch (_error) {
    throw new Error('Failed to generate QR code');
  }
}






export function generateTOTPToken(secret: string): string {
  if (!secret || !/^[A-Z2-7]+=*$/i.test(secret)) {
    throw new Error('Invalid base32 secret');
  }

  return authenticator.generate(secret);
}





export function getTOTPTimeRemaining(): number {
  const step = authenticator.options.step || 30;
  const now = Math.floor(Date.now() / 1000);
  return step - (now % step);
}
