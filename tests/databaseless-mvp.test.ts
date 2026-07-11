import { describe, expect, it } from 'vitest';
import { runTinylandDatabaselessAuthMvp } from '../examples/tinyland-databaseless-auth-mvp.js';

describe('Tinyland databaseless auth MVP', () => {
  it('proves handle-first auth primitives without simulating invitation acceptance', async () => {
    const result = await runTinylandDatabaselessAuthMvp();

    expect(result.admin.handle).toBe('jesssullivan');
    expect(result.admin.email).toBeUndefined();
    expect(result.admin.role).toBe('super_admin');
    expect(result.admin.totpEnabled).toBe(true);

    expect(result.totp.verified).toBe(true);
    expect(result.totp.storedForHandle).toBe('jesssullivan');

    expect(result.backupCodes.accepted).toBe(true);
    expect(result.backupCodes.remaining).toBe(2);

    expect(result.sessions.passwordSessionValidWithoutFingerprint).toBe(true);
    expect(result.sessions.evidenceSessionFingerprint).toBe(
      'fp_tinyland_demo_visitor',
    );
    expect(result.sessions.evidenceSessionValidWithFingerprintEvidence).toBe(
      true,
    );
  });
});
