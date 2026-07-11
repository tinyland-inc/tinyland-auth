import { describe, expect, it } from 'vitest';
import { AdminRole } from '../src/index.js';
import { runTinylandDatabaselessAuthMvp } from '../examples/tinyland-databaseless-auth-mvp.js';

describe('Tinyland databaseless auth MVP', () => {
  it('proves the handle-first auth, authorized invite handoff, TOTP, session, and provider shape', async () => {
    const result = await runTinylandDatabaselessAuthMvp({
      authority: '@tummycrypt/tinyland-invitation',
      role: AdminRole.CONTRIBUTOR,
    });

    expect(result.admin.handle).toBe('jesssullivan');
    expect(result.admin.email).toBeUndefined();
    expect(result.admin.role).toBe('super_admin');
    expect(result.admin.totpEnabled).toBe(true);

    expect(result.totp.verified).toBe(true);
    expect(result.totp.storedForHandle).toBe('jesssullivan');

    expect(result.backupCodes.accepted).toBe(true);
    expect(result.backupCodes.remaining).toBe(2);

    expect(result.invitation).toEqual({
      authority: '@tummycrypt/tinyland-invitation',
      role: 'contributor',
      email: undefined,
    });

    expect(result.invitedUser.handle).toBe('trashmonitor');
    expect(result.invitedUser.email).toBeUndefined();
    expect(result.invitedUser.githubId).toBe(424242);
    expect(result.invitedUser.githubLogin).toBe('trashmonitor');

    expect(result.sessions.passwordSessionValidWithoutFingerprint).toBe(true);
    expect(result.sessions.providerSessionFingerprint).toBe(
      'fp_tinyland_demo_visitor',
    );
    expect(result.sessions.providerSessionValidWithFingerprintEvidence).toBe(
      true,
    );

    expect(result.provider).toEqual({
      provider: 'github',
      providerUserId: '424242',
      login: 'trashmonitor',
      twoFactorVerifiedByProvider: true,
    });
  });
});
