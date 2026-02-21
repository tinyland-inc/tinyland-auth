/**
 * Credentials Helper Utilities
 *
 * Helper functions for integrating credentials generation.
 * Framework-agnostic: uses standard Web APIs (Response).
 *
 * @module @tummycrypt/tinyland-auth/credentials/helpers
 */

import { generateTextCredentialsCard, type CredentialsCardData } from './generator.js';
import { generateTOTPSecret, generateTOTPUri, generateTempPassword } from '../totp/compat.js';

export interface UserCredentials {
  username: string;
  displayName: string;
  email: string;
  tempPassword?: string;
  totpSecret?: string;
}

/**
 * Generate complete user credentials with TOTP setup
 */
export async function generateUserCredentials(
  username: string,
  displayName: string,
  email: string,
  issuer: string = 'Tinyland.dev'
): Promise<UserCredentials & { credentialsText: string }> {
  // Generate secure credentials
  const tempPassword = generateTempPassword(12);
  const totpSecret = generateTOTPSecret();
  const totpUri = generateTOTPUri(totpSecret, issuer, username);

  // Generate text-based credentials card
  const cardData: CredentialsCardData = {
    username,
    displayName,
    tempPassword,
    totpUri,
    issuer,
  };

  const credentialsText = generateTextCredentialsCard(cardData);

  return {
    username,
    displayName,
    email,
    tempPassword,
    totpSecret,
    credentialsText,
  };
}

/**
 * Create a downloadable credentials response
 */
export function createCredentialsDownloadResponse(
  credentialsText: string,
  username: string
): Response {
  const filename = `credentials-${username}-${Date.now()}.txt`;

  const body = new TextEncoder().encode(credentialsText);
  return new Response(body, {
    headers: {
      'Content-Type': 'text/plain',
      'Content-Disposition': `attachment; filename="${filename}"`,
      'Cache-Control': 'no-store, no-cache, must-revalidate',
      'Pragma': 'no-cache',
      'Expires': '0',
    },
  });
}

/**
 * Email-friendly HTML template for credentials
 */
export function generateCredentialsEmailHtml(
  credentials: UserCredentials,
  includeCard: boolean = false
): string {
  const maskedPassword = (pwd: string) => {
    if (pwd.length <= 4) return '--------';
    return `${pwd.substring(0, 2)}${'*'.repeat(pwd.length - 4)}${pwd.substring(pwd.length - 2)}`;
  };

  return `
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <title>Your Account Credentials</title>
  <style>
    body {
      font-family: Arial, sans-serif;
      line-height: 1.6;
      color: #333;
      max-width: 600px;
      margin: 0 auto;
      padding: 20px;
    }
    .header {
      background-color: #e91e63;
      color: white;
      padding: 20px;
      text-align: center;
      border-radius: 8px 8px 0 0;
    }
    .content {
      background-color: #f9f9f9;
      padding: 30px;
      border: 1px solid #ddd;
      border-radius: 0 0 8px 8px;
    }
    .credentials-box {
      background-color: white;
      border: 1px solid #ddd;
      padding: 20px;
      margin: 20px 0;
      border-radius: 5px;
    }
    .credentials-box h3 {
      margin-top: 0;
      color: #e91e63;
    }
    .field {
      margin: 10px 0;
    }
    .field-label {
      font-weight: bold;
      display: inline-block;
      width: 120px;
    }
    .field-value {
      font-family: monospace;
      background-color: #f5f5f5;
      padding: 5px 10px;
      border-radius: 3px;
      display: inline-block;
    }
    .warning {
      background-color: #ffebee;
      border: 1px solid #ffcdd2;
      color: #c62828;
      padding: 15px;
      border-radius: 5px;
      margin: 20px 0;
    }
    .steps {
      background-color: #e8f5e9;
      border: 1px solid #c8e6c9;
      padding: 15px;
      border-radius: 5px;
      margin: 20px 0;
    }
    .steps ol {
      margin: 10px 0 0 0;
      padding-left: 20px;
    }
    .footer {
      text-align: center;
      color: #666;
      font-size: 12px;
      margin-top: 30px;
    }
  </style>
</head>
<body>
  <div class="header">
    <h1>Welcome</h1>
  </div>

  <div class="content">
    <p>Hello ${credentials.displayName},</p>

    <p>Your account has been created. Below are your login credentials and instructions for setting up two-factor authentication.</p>

    <div class="credentials-box">
      <h3>Your Login Credentials</h3>
      <div class="field">
        <span class="field-label">Username:</span>
        <span class="field-value">${credentials.username}</span>
      </div>
      <div class="field">
        <span class="field-label">Email:</span>
        <span class="field-value">${credentials.email}</span>
      </div>
      <div class="field">
        <span class="field-label">Password:</span>
        <span class="field-value">${credentials.tempPassword ? maskedPassword(credentials.tempPassword) : 'See attached card'}</span>
      </div>
    </div>

    <div class="steps">
      <h3>Setup Instructions</h3>
      <ol>
        <li>Download an authenticator app on your phone (Google Authenticator, Authy, or similar)</li>
        <li>${includeCard ? 'Open the attached credentials card and scan the QR code' : 'Use the QR code provided by your administrator'}</li>
        <li>Log in using your username and temporary password</li>
        <li>Enter the 6-digit code from your authenticator app</li>
        <li>Change your password immediately after first login</li>
      </ol>
    </div>

    <div class="warning">
      <strong>Security Notice:</strong>
      <ul style="margin: 10px 0 0 0; padding-left: 20px;">
        <li>Keep your credentials secure and do not share them</li>
        <li>Change your temporary password immediately after first login</li>
        <li>Enable two-factor authentication for account security</li>
        <li>If you suspect your account has been compromised, contact us immediately</li>
      </ul>
    </div>
  </div>

  <div class="footer">
    <p>This email contains confidential information</p>
    <p>Generated on ${new Date().toLocaleDateString()} at ${new Date().toLocaleTimeString()}</p>
  </div>
</body>
</html>
  `;
}

/**
 * Generate a secure share link for credentials (time-limited)
 */
export function generateSecureCredentialsLink(
  credentialsId: string,
  expiresInMinutes: number = 60
): { url: string; expiresAt: Date } {
  const expiresAt = new Date(Date.now() + expiresInMinutes * 60 * 1000);

  // Generate a time-limited token
  const token = Buffer.from(JSON.stringify({
    id: credentialsId,
    exp: expiresAt.getTime(),
  })).toString('base64url');

  return {
    url: `/admin/credentials/download/${token}`,
    expiresAt,
  };
}
