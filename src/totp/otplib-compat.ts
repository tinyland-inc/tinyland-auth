import * as otplibModule from "otplib";

type LegacyAuthenticator = {
  options?: {
    step?: number;
    window?: number;
    digits?: number;
    [key: string]: unknown;
  };
  generateSecret: () => string;
  keyuri: (accountName: string, issuer: string, secret: string) => string;
  generate: (secret: string) => string;
  verify: (options: { token: string; secret: string }) => boolean;
  check?: (token: string, secret: string) => boolean;
  checkDelta?: (token: string, secret: string) => number | null;
};

type ModernVerifyResult = boolean | { valid: boolean };

type ModernOtplib = {
  authenticator?: LegacyAuthenticator;
  default?: ModernOtplib & {
    authenticator?: LegacyAuthenticator;
  };
  generateSecret?: (options?: { length?: number }) => string;
  generateURI?: (options: {
    strategy?: "totp";
    issuer: string;
    label: string;
    secret: string;
    digits?: number;
    period?: number;
  }) => string;
  generateSync?: (options: { secret: string; strategy?: "totp" }) => string;
  verify?: (options: {
    secret: string;
    token: string;
    strategy?: "totp";
    epochTolerance?: number;
  }) => Promise<ModernVerifyResult> | ModernVerifyResult;
  verifySync?: (options: {
    secret: string;
    token: string;
    strategy?: "totp";
    epochTolerance?: number;
  }) => ModernVerifyResult;
};

const otplib = otplibModule as unknown as ModernOtplib;

function getDefaultModule(): ModernOtplib | undefined {
  return otplib.default;
}

function getLegacyAuthenticator(): LegacyAuthenticator | undefined {
  return otplib.authenticator ?? getDefaultModule()?.authenticator;
}

function getExport<K extends keyof ModernOtplib>(
  key: K,
): ModernOtplib[K] | undefined {
  return otplib[key] ?? getDefaultModule()?.[key];
}

export function configureAuthenticator(options: {
  step?: number;
  window?: number;
  digits?: number;
}): void {
  const authenticator = getLegacyAuthenticator();
  if (!authenticator) return;

  authenticator.options = {
    ...authenticator.options,
    ...options,
  };
}

export function generateAuthenticatorSecret(): string {
  const authenticator = getLegacyAuthenticator();
  if (authenticator) {
    return authenticator.generateSecret();
  }

  const generateSecret = getExport("generateSecret");
  if (!generateSecret) {
    throw new Error("otplib generateSecret export is unavailable");
  }

  return generateSecret({ length: 20 });
}

export function generateAuthenticatorUri(
  label: string,
  issuer: string,
  secret: string,
): string {
  const authenticator = getLegacyAuthenticator();
  if (authenticator) {
    return authenticator.keyuri(label, issuer, secret);
  }

  const generateURI = getExport("generateURI");
  if (!generateURI) {
    throw new Error("otplib generateURI export is unavailable");
  }

  return generateURI({
    strategy: "totp",
    issuer,
    label,
    secret,
    digits: 6,
    period: 30,
  });
}

export function generateAuthenticatorToken(secret: string): string {
  const authenticator = getLegacyAuthenticator();
  if (authenticator) {
    return authenticator.generate(secret);
  }

  const generateSync = getExport("generateSync");
  if (!generateSync) {
    throw new Error("otplib generateSync export is unavailable");
  }

  return generateSync({ strategy: "totp", secret });
}

function normalizeVerifyResult(result: ModernVerifyResult): boolean {
  return typeof result === "boolean" ? result : result.valid;
}

export async function verifyAuthenticatorToken(
  secret: string,
  token: string,
): Promise<boolean> {
  const authenticator = getLegacyAuthenticator();
  if (authenticator) {
    return authenticator.verify({ token, secret });
  }

  const verify = getExport("verify");
  if (verify) {
    return normalizeVerifyResult(
      await verify({
        strategy: "totp",
        secret,
        token,
        epochTolerance: 30,
      }),
    );
  }

  const verifySync = getExport("verifySync");
  if (verifySync) {
    return normalizeVerifyResult(
      verifySync({
        strategy: "totp",
        secret,
        token,
        epochTolerance: 30,
      }),
    );
  }

  throw new Error("otplib verify export is unavailable");
}

export function getAuthenticatorStep(): number {
  return getLegacyAuthenticator()?.options?.step ?? 30;
}

/**
 * Returns how many time-steps away from the current step the token matched,
 * within the configured verification window (e.g. -1, 0, +1 for window=1), or
 * `null` when the token is invalid. This is the primitive that lets callers
 * derive the absolute time-step a code was minted for and enforce single-use
 * (replay) protection: absoluteStep = currentStep + delta.
 */
export function getAuthenticatorCheckDelta(
  secret: string,
  token: string,
): number | null {
  const authenticator = getLegacyAuthenticator();

  if (authenticator && typeof authenticator.checkDelta === "function") {
    const delta = authenticator.checkDelta(token, secret);
    return typeof delta === "number" ? delta : null;
  }

  // Fallback for otplib builds that only expose a boolean check/verify: we
  // cannot recover the exact delta, so treat a valid token as the current
  // step (delta 0). Replay protection then degrades to same-step rejection,
  // which is still strictly better than no protection.
  if (authenticator && typeof authenticator.verify === "function") {
    return authenticator.verify({ token, secret }) ? 0 : null;
  }

  throw new Error("otplib checkDelta/verify export is unavailable");
}
