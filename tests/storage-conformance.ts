import { createHash } from 'crypto';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { IStorageAdapter } from '../src/storage/interface.js';
import {
  FirstUserBootstrapConflictError,
  isValidInertFirstUserClaim,
  type FirstUserBootstrapFinalization,
  type InertFirstUserClaim,
} from '../src/storage/firstUserBootstrap.js';

const TENANT = '12345678-1234-4123-8123-123456789abc';
const SYNTHETIC_BCRYPT_HASH = `$2b$04$${'A'.repeat(53)}`;

export interface StorageConformanceHarness {
  storage: IStorageAdapter;
  cleanup(): Promise<void>;
}

export type StorageConformanceFactory = () => Promise<StorageConformanceHarness>;

function syntheticHash(label: string): string {
  return createHash('sha256').update(`synthetic-${label}`).digest('hex');
}

export function makeClaim(
  overrides: Partial<InertFirstUserClaim> = {},
): InertFirstUserClaim {
  return {
    version: 1,
    tenantId: TENANT,
    attemptId: 'synthetic-attempt-1',
    actor: {
      id: 'synthetic-user-1',
      handle: 'bootstrap_admin',
      isActive: false,
      totpEnabled: false,
      sessionAuthority: false,
      backupCodesGenerated: false,
    },
    claimedAt: new Date(Date.now() - 1000).toISOString(),
    ...overrides,
  };
}

export function makeFinalization(
  claim: InertFirstUserClaim,
): FirstUserBootstrapFinalization {
  const finalizedAt = new Date().toISOString();
  return {
    version: 1,
    tenantId: claim.tenantId,
    attemptId: claim.attemptId,
    finalizedAt,
    user: {
      id: claim.actor.id,
      handle: claim.actor.handle,
      displayName: 'Synthetic Bootstrap Admin',
      passwordHash: SYNTHETIC_BCRYPT_HASH,
      totpEnabled: true,
      totpSecretId: claim.actor.handle,
      role: 'super_admin',
      isActive: true,
      needsOnboarding: false,
      onboardingStep: 0,
      createdAt: claim.claimedAt,
      updatedAt: finalizedAt,
    },
    totpSecret: {
      userId: claim.actor.id,
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
      userId: claim.actor.id,
      generatedAt: finalizedAt,
      codes: [
        {
          id: 'synthetic-backup-1',
          hash: syntheticHash('backup-1'),
          used: false,
        },
        {
          id: 'synthetic-backup-2',
          hash: syntheticHash('backup-2'),
          used: false,
        },
      ],
    },
  };
}

export function describeStorageConformance(
  name: string,
  createHarness: StorageConformanceFactory,
): void {
  describe(`${name} atomic first-user bootstrap storage conformance`, () => {
    let harness: StorageConformanceHarness;
    let storage: IStorageAdapter;

    beforeEach(async () => {
      harness = await createHarness();
      storage = harness.storage;
      await storage.init();
    });

    afterEach(async () => {
      await storage.close();
      await harness.cleanup();
    });

    it('allows exactly one of two concurrent claims to win', async () => {
      const first = makeClaim();
      const second = makeClaim({
        attemptId: 'synthetic-attempt-2',
        actor: { ...makeClaim().actor, id: 'synthetic-user-2' },
      });

      const results = await Promise.allSettled([
        storage.claimFirstUserBootstrap(first),
        storage.claimFirstUserBootstrap(second),
      ]);

      expect(results.filter((result) => result.status === 'fulfilled')).toHaveLength(1);
      const rejected = results.find((result) => result.status === 'rejected');
      expect(rejected?.status).toBe('rejected');
      if (rejected?.status === 'rejected') {
        expect(rejected.reason).toBeInstanceOf(FirstUserBootstrapConflictError);
      }
    });

    it('rejects active or credentialed claims through the reusable validator', async () => {
      const active = makeClaim();
      (active.actor as { isActive: boolean }).isActive = true;
      expect(isValidInertFirstUserClaim(active)).toBe(false);
      await expect(storage.claimFirstUserBootstrap(active)).rejects.toThrow(/inert/);

      const credentialed = makeClaim();
      (credentialed.actor as unknown as { passwordHash: string }).passwordHash =
        SYNTHETIC_BCRYPT_HASH;
      expect(isValidInertFirstUserClaim(credentialed)).toBe(false);
      await expect(storage.claimFirstUserBootstrap(credentialed)).rejects.toThrow(/inert/);
    });

    it('keeps a successful claim inert until finalization', async () => {
      const claim = makeClaim();
      await storage.claimFirstUserBootstrap(claim);

      expect(await storage.hasUsers()).toBe(false);
      expect(await storage.getUser(claim.actor.id)).toBeNull();
      expect(await storage.getTOTPSecret(claim.actor.handle)).toBeNull();
      expect(await storage.getBackupCodes(claim.actor.id)).toBeNull();
      await expect(
        storage.createSession(claim.actor.id, { id: claim.actor.id }),
      ).rejects.toThrow(/session authority/);
      await expect(
        storage.saveTOTPSecret(claim.actor.handle, makeFinalization(claim).totpSecret),
      ).rejects.toThrow(/before finalization/);
      await expect(
        storage.saveBackupCodes(claim.actor.id, makeFinalization(claim).backupCodes),
      ).rejects.toThrow(/before finalization/);
    });

    it('rejects a claim when the actor already has a session', async () => {
      const claim = makeClaim();
      await storage.createSession(claim.actor.id, { id: claim.actor.id });
      await expect(storage.claimFirstUserBootstrap(claim)).rejects.toThrow(
        /already has session or factor state/,
      );
    });

    it('replays an exact expired claim and safely replaces an abandoned one', async () => {
      const startedAt = Date.now();
      vi.useFakeTimers();
      try {
        vi.setSystemTime(startedAt);
        const original = makeClaim({
          claimedAt: new Date(startedAt).toISOString(),
        });
        await storage.claimFirstUserBootstrap(original);

        vi.setSystemTime(startedAt + 11 * 60 * 1000);
        await expect(
          storage.claimFirstUserBootstrap(structuredClone(original)),
        ).resolves.toEqual(original);

        const replacement = makeClaim({
          attemptId: 'synthetic-attempt-replacement',
          actor: {
            ...original.actor,
            id: 'synthetic-user-replacement',
            handle: 'replacement_admin',
          },
          claimedAt: new Date(startedAt + 11 * 60 * 1000).toISOString(),
        });
        await expect(storage.claimFirstUserBootstrap(replacement)).resolves.toEqual(
          replacement,
        );
        await expect(
          storage.finalizeFirstUserBootstrap(makeFinalization(original)),
        ).rejects.toThrow(/does not match|active claim/i);
      } finally {
        vi.useRealTimers();
      }
    });

    it('rejects backdated finalization after the server-side claim window', async () => {
      const startedAt = Date.now();
      vi.useFakeTimers();
      try {
        vi.setSystemTime(startedAt);
        const claim = makeClaim({
          claimedAt: new Date(startedAt).toISOString(),
        });
        const finalization = makeFinalization(claim);
        await storage.claimFirstUserBootstrap(claim);

        vi.setSystemTime(startedAt + 12 * 60 * 1000);
        await expect(
          storage.finalizeFirstUserBootstrap(finalization),
        ).rejects.toThrow(/outside the active claim window/i);
        expect(await storage.hasUsers()).toBe(false);
      } finally {
        vi.useRealTimers();
      }
    });

    it('returns the immutable receipt for an exact finalization replay', async () => {
      const claim = makeClaim();
      const finalization = makeFinalization(claim);
      await storage.claimFirstUserBootstrap(claim);

      const receipt = await storage.finalizeFirstUserBootstrap(finalization);
      const replay = await storage.finalizeFirstUserBootstrap(finalization);

      expect(replay).toEqual(receipt);
      expect(await storage.getFirstUserBootstrapReceipt(TENANT)).toEqual(receipt);
      expect(await storage.getUser(claim.actor.id)).toEqual(finalization.user);
      expect(await storage.getTOTPSecret(claim.actor.handle)).toEqual(
        finalization.totpSecret,
      );
      expect(await storage.getBackupCodes(claim.actor.id)).toEqual(
        finalization.backupCodes,
      );
    });

    it('returns one receipt for concurrent exact finalization', async () => {
      const claim = makeClaim();
      const finalization = makeFinalization(claim);
      await storage.claimFirstUserBootstrap(claim);

      const receipts = await Promise.all([
        storage.finalizeFirstUserBootstrap(finalization),
        storage.finalizeFirstUserBootstrap(finalization),
      ]);
      expect(receipts[0]).toEqual(receipts[1]);
    });

    it('rejects a mismatched finalization replay', async () => {
      const claim = makeClaim();
      const finalization = makeFinalization(claim);
      await storage.claimFirstUserBootstrap(claim);
      await storage.finalizeFirstUserBootstrap(finalization);

      const mismatch = structuredClone(finalization);
      mismatch.user.displayName = 'Different Synthetic Admin';
      await expect(storage.finalizeFirstUserBootstrap(mismatch)).rejects.toThrow(
        /immutable completion receipt/,
      );
    });

    it('does not change the receipt when mutable current state changes', async () => {
      const claim = makeClaim();
      const finalization = makeFinalization(claim);
      await storage.claimFirstUserBootstrap(claim);
      const receipt = await storage.finalizeFirstUserBootstrap(finalization);

      await storage.updateUser(claim.actor.id, { displayName: 'Updated Current Name' });
      await storage.saveTOTPSecret(claim.actor.handle, {
        ...finalization.totpSecret,
        version: 2,
      });
      await storage.saveBackupCodes(claim.actor.id, {
        ...finalization.backupCodes,
        lastUsedAt: new Date().toISOString(),
        codes: finalization.backupCodes.codes.map((code, index) =>
          index === 0
            ? { ...code, used: true, usedAt: new Date().toISOString() }
            : code,
        ),
      });

      expect(await storage.getFirstUserBootstrapReceipt(TENANT)).toEqual(receipt);
      expect(await storage.finalizeFirstUserBootstrap(finalization)).toEqual(receipt);
      expect((await storage.getUser(claim.actor.id))?.displayName).toBe(
        'Updated Current Name',
      );
    });

    it('rejects deletion of claimed and finalized actors', async () => {
      const claim = makeClaim();
      const finalization = makeFinalization(claim);
      await storage.claimFirstUserBootstrap(claim);
      await expect(storage.deleteUser(claim.actor.id)).rejects.toThrow(/claimed/);

      await storage.finalizeFirstUserBootstrap(finalization);
      const session = await storage.createSession(claim.actor.id, finalization.user);
      await expect(storage.deleteUser(claim.actor.id)).rejects.toThrow(/finalized/);
      expect(await storage.getSession(session.id)).not.toBeNull();
    });

    it('keeps session identity immutable and returned sessions detached', async () => {
      const unrelatedUserId = 'unrelated-session-user';
      const session = await storage.createSession(unrelatedUserId, {
        id: unrelatedUserId,
        handle: 'unrelated_session_user',
        role: 'member',
      });
      const claim = makeClaim();
      await storage.claimFirstUserBootstrap(claim);

      await expect(storage.updateSession(session.id, {
        userId: claim.actor.id,
      })).rejects.toThrow(/identity is immutable/i);
      await expect(storage.updateSession(session.id, {
        user: { ...session.user!, id: claim.actor.id },
      })).rejects.toThrow(/identity is immutable/i);

      const returned = await storage.getSession(session.id);
      expect(returned).not.toBeNull();
      returned!.userId = claim.actor.id;
      returned!.user!.id = claim.actor.id;
      expect(await storage.getSession(session.id)).toMatchObject({
        userId: unrelatedUserId,
        user: { id: unrelatedUserId },
      });
    });

    it('revokes sessions before deleting an ordinary non-finalized user', async () => {
      const now = new Date().toISOString();
      const user = await storage.createUser({
        handle: 'ordinary_user',
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

      expect(await storage.deleteUser(user.id)).toBe(true);
      expect(await storage.getSession(session.id)).toBeNull();
      expect(await storage.getUser(user.id)).toBeNull();
    });

    it('rejects invalid bcrypt, factor-use, backup uniqueness, and timestamps', async () => {
      const invalidCases: Array<(value: FirstUserBootstrapFinalization) => void> = [
        (value) => { value.user.passwordHash = '$2b$04$not-a-bcrypt-hash'; },
        (value) => { value.totpSecret.lastUsedTotpStep = 1; },
        (value) => { value.backupCodes.codes[1].hash = value.backupCodes.codes[0].hash; },
        (value) => {
          value.totpSecret.createdAt = new Date(
            Date.parse(value.finalizedAt) + 1000,
          ).toISOString();
        },
      ];

      for (const mutate of invalidCases) {
        const isolated = await createHarness();
        await isolated.storage.init();
        try {
          const claim = makeClaim();
          const finalization = makeFinalization(claim);
          mutate(finalization);
          await isolated.storage.claimFirstUserBootstrap(claim);
          await expect(
            isolated.storage.finalizeFirstUserBootstrap(finalization),
          ).rejects.toThrow();
          expect(await isolated.storage.hasUsers()).toBe(false);
        } finally {
          await isolated.storage.close();
          await isolated.cleanup();
        }
      }
    });
  });
}
