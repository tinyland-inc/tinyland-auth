import { createHash } from 'crypto';
import type {
  AdminUser,
  BackupCodeSet,
  EncryptedTOTPSecret,
} from '../types/auth.js';

export const FIRST_USER_BOOTSTRAP_CLAIM_MAX_AGE_MS = 10 * 60 * 1000;
const CLOCK_SKEW_MS = 60 * 1000;
const BCRYPT_HASH_RE =
  /^\$2[aby]\$(?:0[4-9]|[12]\d|3[01])\$[./A-Za-z0-9]{53}$/;
const BACKUP_CODE_HASH_RE = /^[a-f0-9]{64}$/i;

export interface InertFirstUserActorClaim {
  id: string;
  handle: string;
  isActive: false;
  totpEnabled: false;
  sessionAuthority: false;
  backupCodesGenerated: false;
}

export interface InertFirstUserClaim {
  version: 1;
  tenantId: string;
  attemptId: string;
  actor: InertFirstUserActorClaim;
  claimedAt: string;
}

export interface FirstUserBootstrapFinalization {
  version: 1;
  tenantId: string;
  attemptId: string;
  finalizedAt: string;
  user: AdminUser;
  totpSecret: EncryptedTOTPSecret;
  backupCodes: BackupCodeSet;
}

export interface FirstUserBootstrapReceipt {
  version: 1;
  tenantId: string;
  attemptId: string;
  userId: string;
  handle: string;
  claimedAt: string;
  finalizedAt: string;
  materialDigest: string;
}

export interface FirstUserBootstrapReceiptExpectation {
  claim: InertFirstUserClaim;
  finalization: FirstUserBootstrapFinalization;
}

export class FirstUserBootstrapConflictError extends Error {
  readonly code = 'FIRST_USER_BOOTSTRAP_CONFLICT';

  constructor(message: string) {
    super(message);
    this.name = 'FirstUserBootstrapConflictError';
  }
}

export class FirstUserBootstrapValidationError extends Error {
  readonly code = 'FIRST_USER_BOOTSTRAP_INVALID';

  constructor(message: string) {
    super(message);
    this.name = 'FirstUserBootstrapValidationError';
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isBoundedIdentity(value: unknown): value is string {
  return (
    typeof value === 'string' &&
    value.length > 0 &&
    value.length <= 256 &&
    !value.includes('\0')
  );
}

function isSafeActorId(value: unknown): value is string {
  return (
    isBoundedIdentity(value) &&
    /^[A-Za-z0-9][A-Za-z0-9._:-]*$/.test(value)
  );
}

function parseIso(value: unknown): number | null {
  if (typeof value !== 'string') return null;
  const timestamp = Date.parse(value);
  if (!Number.isFinite(timestamp)) return null;
  return new Date(timestamp).toISOString() === value ? timestamp : null;
}

function hasForbiddenClaimMaterial(actor: Record<string, unknown>): boolean {
  return [
    'passwordHash',
    'role',
    'permissions',
    'totpSecretId',
    'totpSecret',
    'backupCodes',
    'sessionIds',
  ].some((field) => Object.prototype.hasOwnProperty.call(actor, field));
}

/**
 * Validate that a first-user claim contains identity and freshness only.
 * Claims must never carry credentials, roles, factors, backup codes, or
 * session authority; those become usable together only at finalization.
 */
export function isValidInertFirstUserClaim(
  value: unknown,
  nowMs: number = Date.now(),
): value is InertFirstUserClaim {
  if (!isRecord(value) || !isRecord(value.actor)) return false;
  if (value.version !== 1) return false;
  if (!isBoundedIdentity(value.tenantId)) return false;
  if (!isBoundedIdentity(value.attemptId)) return false;

  const claimedAt = parseIso(value.claimedAt);
  if (claimedAt === null) return false;
  if (claimedAt > nowMs + CLOCK_SKEW_MS) return false;
  if (claimedAt < nowMs - FIRST_USER_BOOTSTRAP_CLAIM_MAX_AGE_MS) return false;

  const actor = value.actor;
  if (!isSafeActorId(actor.id)) return false;
  if (
    typeof actor.handle !== 'string' ||
    !/^[a-zA-Z][a-zA-Z0-9_-]{2,29}$/.test(actor.handle)
  ) {
    return false;
  }
  if (actor.isActive !== false) return false;
  if (actor.totpEnabled !== false) return false;
  if (actor.sessionAuthority !== false) return false;
  if (actor.backupCodesGenerated !== false) return false;
  return !hasForbiddenClaimMaterial(actor);
}

export function isStructurallyValidInertFirstUserClaim(
  value: unknown,
): value is InertFirstUserClaim {
  if (!isRecord(value)) return false;
  const claimedAt = parseIso(value.claimedAt);
  return claimedAt !== null && isValidInertFirstUserClaim(value, claimedAt);
}

export function isExpiredInertFirstUserClaim(
  claim: InertFirstUserClaim,
  nowMs: number = Date.now(),
): boolean {
  const claimedAt = parseIso(claim.claimedAt);
  return (
    claimedAt === null ||
    claimedAt < nowMs - FIRST_USER_BOOTSTRAP_CLAIM_MAX_AGE_MS
  );
}

function stableJson(value: unknown): string | undefined {
  if (Array.isArray(value)) {
    return `[${value.map((item) => stableJson(item) ?? 'null').join(',')}]`;
  }
  if (isRecord(value)) {
    const entries: string[] = [];
    for (const key of Object.keys(value).sort()) {
      const serialized = stableJson(value[key]);
      if (serialized !== undefined) {
        entries.push(`${JSON.stringify(key)}:${serialized}`);
      }
    }
    return `{${entries.join(',')}}`;
  }
  return JSON.stringify(value);
}

export function firstUserBootstrapValueDigest(value: unknown): string {
  return createHash('sha256').update(stableJson(value) ?? 'null').digest('hex');
}

export function firstUserBootstrapMaterialDigest(
  finalization: FirstUserBootstrapFinalization,
): string {
  return firstUserBootstrapValueDigest(finalization);
}

function assertTimestampInFinalizationWindow(
  label: string,
  value: unknown,
  claimedAt: number,
  finalizedAt: number,
): void {
  const timestamp = parseIso(value);
  if (timestamp === null || timestamp < claimedAt || timestamp > finalizedAt) {
    throw new FirstUserBootstrapValidationError(
      `${label} must be an ISO timestamp between claim and finalization`,
    );
  }
}

export function assertValidFirstUserBootstrapFinalization(
  claim: InertFirstUserClaim,
  finalization: unknown,
  nowMs: number = Date.now(),
): asserts finalization is FirstUserBootstrapFinalization {
  if (!isRecord(finalization) || finalization.version !== 1) {
    throw new FirstUserBootstrapValidationError('Invalid bootstrap finalization');
  }
  if (
    finalization.tenantId !== claim.tenantId ||
    finalization.attemptId !== claim.attemptId
  ) {
    throw new FirstUserBootstrapConflictError(
      'Bootstrap tenant or attempt does not match the active claim',
    );
  }

  const claimedAt = parseIso(claim.claimedAt);
  const finalizedAt = parseIso(finalization.finalizedAt);
  if (claimedAt === null || finalizedAt === null) {
    throw new FirstUserBootstrapValidationError('Invalid bootstrap timestamps');
  }
  if (
    finalizedAt < claimedAt ||
    finalizedAt > claimedAt + FIRST_USER_BOOTSTRAP_CLAIM_MAX_AGE_MS ||
    finalizedAt > nowMs + CLOCK_SKEW_MS ||
    nowMs > claimedAt + FIRST_USER_BOOTSTRAP_CLAIM_MAX_AGE_MS + CLOCK_SKEW_MS
  ) {
    throw new FirstUserBootstrapValidationError(
      'Finalization timestamp is outside the active claim window',
    );
  }

  const user = finalization.user;
  if (!isRecord(user)) {
    throw new FirstUserBootstrapValidationError('Finalization user is required');
  }
  if (user.id !== claim.actor.id || user.handle !== claim.actor.handle) {
    throw new FirstUserBootstrapConflictError(
      'Finalization user does not match the claimed actor',
    );
  }
  const materialTenantId = user.tenantId;
  if (materialTenantId !== undefined && materialTenantId !== claim.tenantId) {
    throw new FirstUserBootstrapConflictError(
      'Finalization user tenant does not match the claim',
    );
  }
  if (user.isActive !== true || user.role !== 'super_admin') {
    throw new FirstUserBootstrapValidationError(
      'Finalized first user must be an active super_admin',
    );
  }
  if (user.totpEnabled !== true || user.totpSecretId !== user.handle) {
    throw new FirstUserBootstrapValidationError(
      'Finalized first user must reference its enrolled TOTP factor',
    );
  }
  if (typeof user.passwordHash !== 'string' || !BCRYPT_HASH_RE.test(user.passwordHash)) {
    throw new FirstUserBootstrapValidationError(
      'Finalized first user passwordHash must be a structurally valid bcrypt hash',
    );
  }
  assertTimestampInFinalizationWindow(
    'user.createdAt',
    user.createdAt,
    claimedAt,
    finalizedAt,
  );
  assertTimestampInFinalizationWindow(
    'user.updatedAt',
    user.updatedAt,
    claimedAt,
    finalizedAt,
  );

  const totp = finalization.totpSecret;
  if (!isRecord(totp)) {
    throw new FirstUserBootstrapValidationError('TOTP factor is required');
  }
  if (totp.userId !== user.id || totp.handle !== user.handle) {
    throw new FirstUserBootstrapConflictError(
      'TOTP factor identity does not match the finalized user',
    );
  }
  for (const field of ['encryptedSecret', 'iv', 'authTag', 'salt'] as const) {
    if (!isBoundedIdentity(totp[field])) {
      throw new FirstUserBootstrapValidationError(`TOTP factor ${field} is required`);
    }
  }
  if (
    totp.lastUsedAt !== undefined ||
    totp.lastUsedTotpStep !== undefined ||
    totp.backupCodesGenerated !== true ||
    !Number.isInteger(totp.version) ||
    (totp.version as number) < 1
  ) {
    throw new FirstUserBootstrapValidationError(
      'TOTP factor must be fresh, unused, and versioned',
    );
  }
  assertTimestampInFinalizationWindow(
    'totpSecret.createdAt',
    totp.createdAt,
    claimedAt,
    finalizedAt,
  );

  const backupCodes = finalization.backupCodes;
  if (!isRecord(backupCodes) || backupCodes.userId !== user.id) {
    throw new FirstUserBootstrapConflictError(
      'Backup-code identity does not match the finalized user',
    );
  }
  if (backupCodes.lastUsedAt !== undefined || !Array.isArray(backupCodes.codes)) {
    throw new FirstUserBootstrapValidationError(
      'Backup-code set must be fresh and unused',
    );
  }
  if (backupCodes.codes.length === 0) {
    throw new FirstUserBootstrapValidationError(
      'At least one fresh backup-code record is required',
    );
  }
  assertTimestampInFinalizationWindow(
    'backupCodes.generatedAt',
    backupCodes.generatedAt,
    claimedAt,
    finalizedAt,
  );

  const ids = new Set<string>();
  const hashes = new Set<string>();
  for (const code of backupCodes.codes) {
    if (
      !isRecord(code) ||
      !isBoundedIdentity(code.id) ||
      typeof code.hash !== 'string' ||
      !BACKUP_CODE_HASH_RE.test(code.hash) ||
      code.used !== false ||
      code.usedAt !== undefined ||
      ids.has(code.id) ||
      hashes.has(code.hash)
    ) {
      throw new FirstUserBootstrapValidationError(
        'Backup-code records must be fresh, unused, and unique',
      );
    }
    ids.add(code.id);
    hashes.add(code.hash);
  }
}

export function createFirstUserBootstrapReceipt(
  claim: InertFirstUserClaim,
  finalization: FirstUserBootstrapFinalization,
): FirstUserBootstrapReceipt {
  return {
    version: 1,
    tenantId: claim.tenantId,
    attemptId: claim.attemptId,
    userId: claim.actor.id,
    handle: claim.actor.handle,
    claimedAt: claim.claimedAt,
    finalizedAt: finalization.finalizedAt,
    materialDigest: firstUserBootstrapMaterialDigest(finalization),
  };
}

export function parseFirstUserBootstrapReceipt(
  value: unknown,
  expected?: FirstUserBootstrapReceiptExpectation,
): FirstUserBootstrapReceipt {
  if (!isRecord(value) || value.version !== 1) {
    throw new FirstUserBootstrapValidationError(
      'Invalid first-user bootstrap receipt',
    );
  }
  for (const field of ['tenantId', 'attemptId', 'userId', 'handle'] as const) {
    if (!isBoundedIdentity(value[field])) {
      throw new FirstUserBootstrapValidationError(
        `Bootstrap receipt ${field} is invalid`,
      );
    }
  }
  const claimedAt = parseIso(value.claimedAt);
  const finalizedAt = parseIso(value.finalizedAt);
  if (claimedAt === null || finalizedAt === null || finalizedAt < claimedAt) {
    throw new FirstUserBootstrapValidationError(
      'Bootstrap receipt timestamps are invalid',
    );
  }
  if (
    typeof value.materialDigest !== 'string' ||
    !/^[a-f0-9]{64}$/i.test(value.materialDigest)
  ) {
    throw new FirstUserBootstrapValidationError(
      'Bootstrap receipt materialDigest is invalid',
    );
  }

  const receipt: FirstUserBootstrapReceipt = {
    version: 1,
    tenantId: value.tenantId as string,
    attemptId: value.attemptId as string,
    userId: value.userId as string,
    handle: value.handle as string,
    claimedAt: value.claimedAt as string,
    finalizedAt: value.finalizedAt as string,
    materialDigest: value.materialDigest,
  };
  if (expected) {
    const canonical = createFirstUserBootstrapReceipt(
      expected.claim,
      expected.finalization,
    );
    if (
      firstUserBootstrapValueDigest(receipt) !==
      firstUserBootstrapValueDigest(canonical)
    ) {
      throw new FirstUserBootstrapValidationError(
        'Bootstrap receipt does not match its claim and finalized material',
      );
    }
  }
  return receipt;
}

export function cloneBootstrapValue<T>(value: T): T {
  return structuredClone(value);
}
