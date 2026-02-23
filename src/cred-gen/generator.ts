









export interface CredentialsCardData {
  username: string;
  displayName: string;
  tempPassword: string;
  totpUri: string;
  issuer?: string;
  qrCode?: string;
}

export interface CardDesignOptions {
  width?: number;
  height?: number;
  backgroundColor?: string;
  primaryColor?: string;
  accentColor?: string;
  fontFamily?: string;
}




export function generateTextCredentialsCard(
  data: CredentialsCardData
): string {
  const border = '='.repeat(60);
  const divider = '-'.repeat(60);

  return `
${border}
                    ${data.issuer || 'Tinyland.dev'}
                    Account Credentials
${border}

Username:     ${data.username}
Display Name: ${data.displayName}
Password:     ${maskPassword(data.tempPassword)}

${divider}
                 Two-Factor Authentication

${data.totpUri}

Scan the above URL with your authenticator app
or enter it manually.

${divider}
                    Setup Instructions

1. Download an authenticator app (Google Authenticator, Authy)
2. Scan the QR code or enter the URL above
3. Enter the 6-digit code when logging in
4. Change your temporary password after first login

${divider}
                   SECURITY WARNING

- Keep this information secure
- Do not share your credentials
- Change your password immediately after first login
- If compromised, contact your administrator

${border}
Generated: ${new Date().toISOString()}
${border}
`;
}




export function maskPassword(password: string): string {
  if (password.length <= 4) {
    return '--------';
  }

  const first = password.substring(0, 2);
  const last = password.substring(password.length - 2);
  const masked = '*'.repeat(password.length - 4);

  return `${first}${masked}${last}`;
}




export function escapeXml(text: string): string {
  return text
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;');
}
