import {
  AdminRole,
  createAuthConfig,
  createBackupCodeSet,
  createSessionManager,
  generateBackupCodes,
  hashPassword,
  MemoryStorageAdapter,
  TOTPService,
  verifyBackupCode,
  type AdminUser,
  type SessionMetadata,
} from '../src/index.js';

export interface FingerprintEvidence {
  visitorId?: string;
  tempoTraceId?: string;
  consentState?: 'granted' | 'denied' | 'unknown';
}

export interface TinylandDatabaselessAuthMvpResult {
  admin: Pick<AdminUser, 'id' | 'handle' | 'email' | 'role' | 'totpEnabled'>;
  totp: {
    verified: boolean;
    storedForHandle: string;
  };
  backupCodes: {
    accepted: boolean;
    remaining: number;
  };
  sessions: {
    passwordSessionValidWithoutFingerprint: boolean;
    evidenceSessionFingerprint?: string;
    evidenceSessionValidWithFingerprintEvidence: boolean;
  };
}

const ENCRYPTION_KEY = 'tinyland-auth-mvp-demo-key-32-chars';

function nowIso(): string {
  return new Date().toISOString();
}

function sessionMetadata(evidence?: FingerprintEvidence): SessionMetadata {
  return {
    clientIp: '127.0.0.1',
    clientIpMasked: '127.0.0.0/24',
    userAgent: 'TinylandAuthMvp/1.0',
    deviceType: 'desktop',
    browserFingerprint: evidence?.visitorId,
  };
}

function handleOnlyUser(
  fields: Pick<AdminUser, 'handle' | 'displayName' | 'role'>,
): Omit<AdminUser, 'id'> {
  const timestamp = nowIso();

  return {
    handle: fields.handle,
    displayName: fields.displayName,
    passwordHash: '',
    totpEnabled: false,
    role: fields.role,
    isActive: true,
    needsOnboarding: false,
    onboardingStep: 0,
    createdAt: timestamp,
    updatedAt: timestamp,
  };
}

export async function runTinylandDatabaselessAuthMvp(): Promise<TinylandDatabaselessAuthMvpResult> {
  const defaults = createAuthConfig();
  const config = createAuthConfig({
    appName: 'Tinyland Auth MVP',
    appUrl: 'https://tinyland.dev',
    session: {
      ...defaults.session,
      maxAge: 24 * 60 * 60 * 1000,
      renewThreshold: 60 * 60 * 1000,
      maxConcurrentSessions: 1,
    },
  });

  const storage = new MemoryStorageAdapter();
  await storage.init();

  const sessionManager = createSessionManager(storage, config.session);
  const totpService = new TOTPService({
    encryptionKey: ENCRYPTION_KEY,
    issuer: 'Tinyland Auth MVP',
  });

  const adminDraft = handleOnlyUser({
    handle: 'jesssullivan',
    displayName: 'Jess Sullivan',
    role: AdminRole.SUPER_ADMIN,
  });
  adminDraft.passwordHash = await hashPassword('correct horse battery staple', {
    rounds: 4,
  });
  adminDraft.totpEnabled = true;

  const admin = await storage.createUser(adminDraft);

  const totpSecret = await totpService.generateSecret(admin.handle);
  const totpToken = totpService.generateToken(totpSecret);
  const totpVerified = await totpService.verifyToken(totpSecret, totpToken);
  const encryptedTotp = totpService.encrypt(totpSecret.secret);

  await storage.saveTOTPSecret(admin.handle, {
    userId: admin.id,
    handle: admin.handle,
    encryptedSecret: encryptedTotp.encrypted,
    iv: encryptedTotp.iv,
    authTag: encryptedTotp.tag,
    salt: encryptedTotp.salt,
    createdAt: nowIso(),
    backupCodesGenerated: false,
    version: 1,
  });

  const storedTotp = await storage.getTOTPSecret(admin.handle);
  if (!storedTotp) {
    throw new Error('MVP failed to store TOTP secret');
  }

  const plainBackupCodes = generateBackupCodes(3);
  const backupCodeSet = createBackupCodeSet(admin.id, plainBackupCodes);
  const backupVerification = verifyBackupCode(
    backupCodeSet,
    plainBackupCodes[0] ?? '',
  );
  await storage.saveBackupCodes(admin.id, backupVerification.codeSet);

  const passwordSession = await sessionManager.createSession(
    admin.id,
    admin,
    sessionMetadata(),
  );
  const validatedPasswordSession = await sessionManager.validateSession(
    passwordSession.id,
  );

  const evidenceSession = await sessionManager.createSession(
    admin.id,
    admin,
    sessionMetadata({
      visitorId: 'fp_tinyland_demo_visitor',
      tempoTraceId: 'trace-demo-auth-001',
      consentState: 'granted',
    }),
  );
  const validatedEvidenceSession = await sessionManager.validateSession(
    evidenceSession.id,
  );

  return {
    admin: {
      id: admin.id,
      handle: admin.handle,
      email: admin.email,
      role: admin.role,
      totpEnabled: admin.totpEnabled,
    },
    totp: {
      verified: totpVerified,
      storedForHandle: storedTotp.handle,
    },
    backupCodes: {
      accepted: backupVerification.valid,
      remaining: backupVerification.codesRemaining,
    },
    sessions: {
      passwordSessionValidWithoutFingerprint: Boolean(
        validatedPasswordSession,
      ),
      evidenceSessionFingerprint: evidenceSession.browserFingerprint,
      evidenceSessionValidWithFingerprintEvidence: Boolean(
        validatedEvidenceSession,
      ),
    },
  };
}
