import { createHash, randomUUID } from 'crypto';
import type { IStorageAdapter } from './interface.js';
import {
  firstUserBootstrapValueDigest,
  type FirstUserBootstrapFinalization,
  type InertFirstUserClaim,
} from './firstUserBootstrap.js';

const SYNTHETIC_BCRYPT_HASH = `$2b$04$${'A'.repeat(53)}`;

export interface FirstUserBootstrapConformanceHarness {
  storage: IStorageAdapter;
  cleanup(): Promise<void>;
}

export type FirstUserBootstrapConformanceHarnessFactory =
  () => Promise<FirstUserBootstrapConformanceHarness>;

export interface FirstUserBootstrapConformanceResult {
  name: string;
  passed: true;
}

export class FirstUserBootstrapConformanceError extends Error {
  constructor(
    readonly caseName: string,
    readonly cause: unknown,
  ) {
    super(
      `First-user bootstrap storage conformance failed: ${caseName}: ${
        cause instanceof Error ? cause.message : String(cause)
      }`,
    );
    this.name = 'FirstUserBootstrapConformanceError';
  }
}

function assert(condition: unknown, message: string): asserts condition {
  if (!condition) throw new Error(message);
}

async function rejects(operation: () => Promise<unknown>): Promise<boolean> {
  try {
    await operation();
    return false;
  } catch {
    return true;
  }
}

function syntheticHash(label: string): string {
  return createHash('sha256').update(`synthetic-${label}`).digest('hex');
}

function createMaterial(): {
  claim: InertFirstUserClaim;
  finalization: FirstUserBootstrapFinalization;
} {
  const claimedAt = new Date(Date.now() - 1000).toISOString();
  const tenantId = randomUUID();
  const userId = randomUUID();
  const claim: InertFirstUserClaim = {
    version: 1,
    tenantId,
    attemptId: randomUUID(),
    actor: {
      id: userId,
      handle: `bootstrap_${userId.slice(0, 8)}`,
      isActive: false,
      totpEnabled: false,
      sessionAuthority: false,
      backupCodesGenerated: false,
    },
    claimedAt,
  };
  const finalizedAt = new Date().toISOString();
  return {
    claim,
    finalization: {
      version: 1,
      tenantId,
      attemptId: claim.attemptId,
      finalizedAt,
      user: {
        id: userId,
        handle: claim.actor.handle,
        passwordHash: SYNTHETIC_BCRYPT_HASH,
        totpEnabled: true,
        totpSecretId: claim.actor.handle,
        role: 'super_admin',
        isActive: true,
        needsOnboarding: false,
        onboardingStep: 0,
        createdAt: claimedAt,
        updatedAt: finalizedAt,
      },
      totpSecret: {
        userId,
        handle: claim.actor.handle,
        encryptedSecret: 'synthetic-encrypted-totp',
        iv: 'synthetic-iv',
        authTag: 'synthetic-auth-tag',
        salt: 'synthetic-salt',
        createdAt: finalizedAt,
        backupCodesGenerated: true,
        version: 1,
      },
      backupCodes: {
        userId,
        generatedAt: finalizedAt,
        codes: [
          { id: randomUUID(), hash: syntheticHash('one'), used: false },
          { id: randomUUID(), hash: syntheticHash('two'), used: false },
        ],
      },
    },
  };
}

async function runCase(
  name: string,
  createHarness: FirstUserBootstrapConformanceHarnessFactory,
  test: (storage: IStorageAdapter) => Promise<void>,
): Promise<FirstUserBootstrapConformanceResult> {
  const harness = await createHarness();
  try {
    await harness.storage.init();
    await test(harness.storage);
    return { name, passed: true };
  } catch (error) {
    throw new FirstUserBootstrapConformanceError(name, error);
  } finally {
    try {
      await harness.storage.close();
    } finally {
      await harness.cleanup();
    }
  }
}

/**
 * Framework-neutral backend contract runner. PG/Redis adapters can invoke this
 * from any test framework by supplying a fresh, isolated tenant/store harness.
 */
export async function runFirstUserBootstrapStorageConformance(
  createHarness: FirstUserBootstrapConformanceHarnessFactory,
): Promise<FirstUserBootstrapConformanceResult[]> {
  const cases: Array<Promise<FirstUserBootstrapConformanceResult>> = [];

  cases.push(runCase('concurrent claims have one winner', createHarness, async (storage) => {
    const first = createMaterial().claim;
    const second = createMaterial().claim;
    second.tenantId = first.tenantId;
    const outcomes = await Promise.allSettled([
      storage.claimFirstUserBootstrap(first),
      storage.claimFirstUserBootstrap(second),
    ]);
    assert(
      outcomes.filter((outcome) => outcome.status === 'fulfilled').length === 1,
      'expected exactly one successful claim',
    );
  }));

  cases.push(runCase('active or credentialed claims are rejected', createHarness, async (storage) => {
    const active = createMaterial().claim;
    (active.actor as { isActive: boolean }).isActive = true;
    assert(
      await rejects(() => storage.claimFirstUserBootstrap(active)),
      'active claim was accepted',
    );

    const credentialed = createMaterial().claim;
    credentialed.tenantId = active.tenantId;
    (credentialed.actor as unknown as { passwordHash: string }).passwordHash =
      SYNTHETIC_BCRYPT_HASH;
    assert(
      await rejects(() => storage.claimFirstUserBootstrap(credentialed)),
      'credentialed claim was accepted',
    );
  }));

  cases.push(runCase('concurrent exact finalization is idempotent', createHarness, async (storage) => {
    const { claim, finalization } = createMaterial();
    await storage.claimFirstUserBootstrap(claim);
    const receipts = await Promise.all([
      storage.finalizeFirstUserBootstrap(finalization),
      storage.finalizeFirstUserBootstrap(finalization),
    ]);
    assert(
      firstUserBootstrapValueDigest(receipts[0]) ===
        firstUserBootstrapValueDigest(receipts[1]),
      'concurrent exact finalization returned different receipts',
    );
  }));

  cases.push(runCase('claim remains inert', createHarness, async (storage) => {
    const { claim } = createMaterial();
    await storage.claimFirstUserBootstrap(claim);
    assert(!(await storage.hasUsers()), 'claim created an active user');
    assert(
      await rejects(() =>
        storage.createSession(claim.actor.id, { id: claim.actor.id })),
      'claimed actor received session authority',
    );
  }));

  cases.push(runCase('receipt survives mutable state changes', createHarness, async (storage) => {
    const { claim, finalization } = createMaterial();
    await storage.claimFirstUserBootstrap(claim);
    const receipt = await storage.finalizeFirstUserBootstrap(finalization);
    await storage.updateUser(claim.actor.id, { displayName: 'Synthetic Current State' });
    const persisted = await storage.getFirstUserBootstrapReceipt(claim.tenantId);
    assert(
      persisted !== null &&
        firstUserBootstrapValueDigest(receipt) ===
          firstUserBootstrapValueDigest(persisted),
      'mutable state changed the immutable receipt',
    );
  }));

  cases.push(runCase('invalid material fails before authority exists', createHarness, async (storage) => {
    const { claim, finalization } = createMaterial();
    finalization.user.passwordHash = 'synthetic-invalid-bcrypt';
    await storage.claimFirstUserBootstrap(claim);
    assert(
      await rejects(() => storage.finalizeFirstUserBootstrap(finalization)),
      'invalid finalization was accepted',
    );
    finalization.user.passwordHash = SYNTHETIC_BCRYPT_HASH;
    finalization.totpSecret.lastUsedTotpStep = 1;
    assert(
      await rejects(() => storage.finalizeFirstUserBootstrap(finalization)),
      'used TOTP factor was accepted',
    );
    delete finalization.totpSecret.lastUsedTotpStep;
    finalization.backupCodes.codes[1].hash = finalization.backupCodes.codes[0].hash;
    assert(
      await rejects(() => storage.finalizeFirstUserBootstrap(finalization)),
      'duplicate backup-code record was accepted',
    );
    assert(!(await storage.hasUsers()), 'invalid finalization created a user');
  }));

  cases.push(runCase('mismatched finalization replay conflicts', createHarness, async (storage) => {
    const { claim, finalization } = createMaterial();
    await storage.claimFirstUserBootstrap(claim);
    await storage.finalizeFirstUserBootstrap(finalization);
    finalization.user.displayName = 'Mismatched Synthetic Replay';
    assert(
      await rejects(() => storage.finalizeFirstUserBootstrap(finalization)),
      'mismatched finalization replay was accepted',
    );
  }));

  cases.push(runCase('bootstrap actors are deletion-protected', createHarness, async (storage) => {
    const { claim, finalization } = createMaterial();
    await storage.claimFirstUserBootstrap(claim);
    assert(
      await rejects(() => storage.deleteUser(claim.actor.id)),
      'claimed actor deletion was accepted',
    );
    await storage.finalizeFirstUserBootstrap(finalization);
    assert(
      await rejects(() => storage.deleteUser(claim.actor.id)),
      'finalized actor deletion was accepted',
    );
  }));

  cases.push(runCase('ordinary user deletion revokes sessions', createHarness, async (storage) => {
    const now = new Date().toISOString();
    const user = await storage.createUser({
      handle: `ordinary_${randomUUID().slice(0, 8)}`,
      passwordHash: SYNTHETIC_BCRYPT_HASH,
      totpEnabled: false,
      role: 'member',
      isActive: true,
      needsOnboarding: false,
      onboardingStep: 0,
      createdAt: now,
      updatedAt: now,
    });
    const session = await storage.createSession(user.id, user);
    assert(await storage.deleteUser(user.id), 'ordinary user was not deleted');
    assert((await storage.getSession(session.id)) === null, 'user session survived deletion');
  }));

  cases.push(runCase('ordinary creation cannot bypass an active claim', createHarness, async (storage) => {
    const { claim } = createMaterial();
    await storage.claimFirstUserBootstrap(claim);
    const timestamp = new Date().toISOString();
    assert(
      await rejects(() => storage.createUser({
        handle: 'bypass_admin',
        passwordHash: SYNTHETIC_BCRYPT_HASH,
        totpEnabled: false,
        role: 'super_admin',
        isActive: true,
        needsOnboarding: false,
        onboardingStep: 0,
        createdAt: timestamp,
        updatedAt: timestamp,
      })),
      'ordinary user creation bypassed the active claim',
    );
  }));

  cases.push(runCase('session identity cannot bypass claimed-actor confinement', createHarness, async (storage) => {
    const { claim } = createMaterial();
    const unrelatedUserId = randomUUID();
    const existingSession = await storage.createSession(unrelatedUserId, {
      id: unrelatedUserId,
      handle: 'unrelated_session_actor',
      role: 'member',
    });
    await storage.claimFirstUserBootstrap(claim);
    assert(
      await rejects(() => storage.createSession('unrelated-user', {
        id: claim.actor.id,
        role: 'super_admin',
      })),
      'mismatched nested session identity bypassed claim confinement',
    );
    assert(
      await rejects(() => storage.updateSession(existingSession.id, {
        userId: claim.actor.id,
      })),
      'session userId was rebound to the claimed actor',
    );
    assert(
      await rejects(() => storage.updateSession(existingSession.id, {
        user: {
          ...(existingSession.user ?? {
            id: unrelatedUserId,
            username: 'unrelated_session_actor',
            name: 'unrelated_session_actor',
            role: 'member',
          }),
          id: claim.actor.id,
        },
      })),
      'nested session identity was rebound to the claimed actor',
    );
    const returned = await storage.getSession(existingSession.id);
    assert(returned !== null, 'ordinary session disappeared');
    returned.userId = claim.actor.id;
    if (returned.user) returned.user.id = claim.actor.id;
    const persisted = await storage.getSession(existingSession.id);
    assert(
      persisted?.userId === unrelatedUserId &&
        persisted.user?.id === unrelatedUserId,
      'returned session alias mutated stored identity',
    );
  }));

  cases.push(runCase('returned bootstrap authority is not a mutable alias', createHarness, async (storage) => {
    const { claim, finalization } = createMaterial();
    await storage.claimFirstUserBootstrap(claim);
    await storage.finalizeFirstUserBootstrap(finalization);

    const user = await storage.getUser(claim.actor.id);
    const totp = await storage.getTOTPSecret(claim.actor.handle);
    const backupCodes = await storage.getBackupCodes(claim.actor.id);
    assert(user !== null && totp !== null && backupCodes !== null, 'finalized material missing');
    user.role = 'viewer';
    totp.encryptedSecret = 'mutated-outside-adapter';
    backupCodes.codes[0].used = true;

    assert((await storage.getUser(claim.actor.id))?.role === 'super_admin', 'user alias mutated authority');
    assert(
      (await storage.getTOTPSecret(claim.actor.handle))?.encryptedSecret ===
        finalization.totpSecret.encryptedSecret,
      'TOTP alias mutated authority',
    );
    assert(
      (await storage.getBackupCodes(claim.actor.id))?.codes[0].used === false,
      'backup-code alias mutated authority',
    );
  }));

  cases.push(runCase('finalized bootstrap factors cannot be deleted independently', createHarness, async (storage) => {
    const { claim, finalization } = createMaterial();
    await storage.claimFirstUserBootstrap(claim);
    await storage.finalizeFirstUserBootstrap(finalization);
    assert(
      await rejects(() => storage.deleteTOTPSecret(claim.actor.handle)),
      'finalized TOTP factor was deleted independently',
    );
    assert(
      await rejects(() => storage.deleteBackupCodes(claim.actor.id)),
      'finalized backup codes were deleted independently',
    );
  }));

  return Promise.all(cases);
}
