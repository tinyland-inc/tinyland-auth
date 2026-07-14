import { promises as fs } from 'fs';
import os from 'os';
import path from 'path';
import { describe, expect, it } from 'vitest';
import { FileStorageAdapter } from '../src/storage/file.js';
import { MemoryStorageAdapter } from '../src/storage/memory.js';
import { runFirstUserBootstrapStorageConformance } from '../src/storage/conformance.js';
import {
  describeStorageConformance,
  makeClaim,
  makeFinalization,
} from './storage-conformance.js';

const TENANT = '12345678-1234-4123-8123-123456789abc';

describeStorageConformance('MemoryStorageAdapter', async () => ({
  storage: new MemoryStorageAdapter(),
  cleanup: async () => undefined,
}));

describeStorageConformance('FileStorageAdapter', async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'tinyland-auth-storage-'));
  return {
    storage: new FileStorageAdapter({
      authDir: path.join(root, 'auth'),
      totpDir: path.join(root, 'totp'),
    }),
    cleanup: async () => fs.rm(root, { recursive: true, force: true }),
  };
});

describe('FileStorageAdapter first-user bootstrap custody', () => {
  it('keeps bootstrap state under totpDir and fails closed on corruption', async () => {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), 'tinyland-auth-custody-'));
    const authDir = path.join(root, 'auth');
    const totpDir = path.join(root, 'totp');
    const storage = new FileStorageAdapter({ authDir, totpDir });
    await storage.init();

    try {
      const bootstrapPath = storage.getFirstUserBootstrapPath(TENANT);
      expect(path.resolve(bootstrapPath).startsWith(path.resolve(totpDir))).toBe(true);
      expect(path.resolve(bootstrapPath).startsWith(path.resolve(authDir))).toBe(false);

      await fs.writeFile(bootstrapPath, '{corrupted-json', 'utf8');
      await expect(storage.getFirstUserBootstrapReceipt(TENANT)).rejects.toThrow();
    } finally {
      await storage.close();
      await fs.rm(root, { recursive: true, force: true });
    }
  });

  it('reopens finalized state durably and rejects a corrupted receipt', async () => {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), 'tinyland-auth-reopen-'));
    const config = {
      authDir: path.join(root, 'auth'),
      totpDir: path.join(root, 'totp'),
    };
    const claim = makeClaim();
    const finalization = makeFinalization(claim);
    const first = new FileStorageAdapter(config);
    await first.init();

    try {
      await first.claimFirstUserBootstrap(claim);
      const receipt = await first.finalizeFirstUserBootstrap(finalization);
      await first.close();

      const reopened = new FileStorageAdapter(config);
      await reopened.init();
      expect(await reopened.getFirstUserBootstrapReceipt(TENANT)).toEqual(receipt);
      expect(await reopened.getUser(claim.actor.id)).toEqual(finalization.user);
      const concurrent = await Promise.all([
        reopened.finalizeFirstUserBootstrap(finalization),
        reopened.finalizeFirstUserBootstrap(finalization),
      ]);
      expect(concurrent).toEqual([receipt, receipt]);
      await reopened.close();

      const bootstrapPath = first.getFirstUserBootstrapPath(TENANT);
      const record = JSON.parse(await fs.readFile(bootstrapPath, 'utf8')) as {
        receipt: { materialDigest: string };
      };
      record.receipt.materialDigest = '0'.repeat(64);
      await fs.writeFile(bootstrapPath, JSON.stringify(record), 'utf8');

      const corrupted = new FileStorageAdapter(config);
      await corrupted.init();
      await expect(corrupted.getFirstUserBootstrapReceipt(TENANT)).rejects.toThrow(
        /corrupted immutable/i,
      );
      await corrupted.close();
    } finally {
      await fs.rm(root, { recursive: true, force: true });
    }
  });

  it('keeps receipt digests stable when optional undefined fields round-trip', async () => {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), 'tinyland-auth-undefined-'));
    const config = {
      authDir: path.join(root, 'auth'),
      totpDir: path.join(root, 'totp'),
    };
    const claim = makeClaim();
    const finalization = makeFinalization(claim);
    (finalization.user as { email?: string }).email = undefined;
    const first = new FileStorageAdapter(config);
    await first.init();

    try {
      await first.claimFirstUserBootstrap(claim);
      const receipt = await first.finalizeFirstUserBootstrap(finalization);
      await first.close();

      const reopened = new FileStorageAdapter(config);
      await reopened.init();
      expect(await reopened.getFirstUserBootstrapReceipt(TENANT)).toEqual(receipt);
      await expect(
        reopened.finalizeFirstUserBootstrap(finalization),
      ).resolves.toEqual(receipt);
      await reopened.close();
    } finally {
      await fs.rm(root, { recursive: true, force: true });
    }
  });

  it('recovers a lock whose recorded owner process is gone', async () => {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), 'tinyland-auth-stale-lock-'));
    const totpDir = path.join(root, 'totp');
    const storage = new FileStorageAdapter({
      authDir: path.join(root, 'auth'),
      totpDir,
    });
    await storage.init();

    try {
      const lockPath = path.join(totpDir, '.first-user-bootstrap.lock');
      await fs.mkdir(lockPath);
      await fs.writeFile(
        path.join(lockPath, 'owner.json'),
        JSON.stringify({
          version: 1,
          pid: 999999,
          token: 'abandoned-owner',
          createdAt: new Date(Date.now() - 60_000).toISOString(),
        }),
        'utf8',
      );

      await expect(storage.claimFirstUserBootstrap(makeClaim())).resolves.toEqual(
        expect.objectContaining({ attemptId: 'synthetic-attempt-1' }),
      );
      await expect(fs.access(lockPath)).rejects.toMatchObject({ code: 'ENOENT' });
    } finally {
      await storage.close();
      await fs.rm(root, { recursive: true, force: true });
    }
  });

  it('serializes claims across separate adapter instances', async () => {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), 'tinyland-auth-two-adapters-'));
    const config = {
      authDir: path.join(root, 'auth'),
      totpDir: path.join(root, 'totp'),
    };
    const first = new FileStorageAdapter(config);
    const second = new FileStorageAdapter(config);
    await Promise.all([first.init(), second.init()]);
    const firstClaim = makeClaim();
    const secondClaim = makeClaim({
      attemptId: 'synthetic-attempt-2',
      actor: {
        ...firstClaim.actor,
        id: 'synthetic-user-2',
        handle: 'bootstrap_second',
      },
    });

    try {
      const results = await Promise.allSettled([
        first.claimFirstUserBootstrap(firstClaim),
        second.claimFirstUserBootstrap(secondClaim),
      ]);
      expect(results.filter((result) => result.status === 'fulfilled')).toHaveLength(1);
      expect(results.filter((result) => result.status === 'rejected')).toHaveLength(1);
    } finally {
      await Promise.all([first.close(), second.close()]);
      await fs.rm(root, { recursive: true, force: true });
    }
  });
});

describe('framework-neutral first-user bootstrap conformance runner', () => {
  it('runs against the memory adapter', async () => {
    const results = await runFirstUserBootstrapStorageConformance(async () => ({
      storage: new MemoryStorageAdapter(),
      cleanup: async () => undefined,
    }));
    expect(results).toHaveLength(13);
  });

  it('runs against the file adapter', async () => {
    const results = await runFirstUserBootstrapStorageConformance(async () => {
      const root = await fs.mkdtemp(path.join(os.tmpdir(), 'tinyland-auth-runner-'));
      return {
        storage: new FileStorageAdapter({
          authDir: path.join(root, 'auth'),
          totpDir: path.join(root, 'totp'),
        }),
        cleanup: async () => fs.rm(root, { recursive: true, force: true }),
      };
    });
    expect(results).toHaveLength(13);
  });
});
