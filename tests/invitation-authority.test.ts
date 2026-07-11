import { access, readFile } from 'node:fs/promises';
import { describe, expect, it } from 'vitest';
import * as publicApi from '../src/index.js';

const readText = (path: string) => readFile(path, 'utf8');

describe('invitation package authority', () => {
  it('exports no invitation minting service from the public package surface', async () => {
    const mintingExports = Object.keys(publicApi).filter((name) =>
      /invitationservice|createinvitation|mintinvitation/i.test(name),
    );
    const packageJson = JSON.parse(await readText('package.json')) as {
      exports?: Record<string, unknown>;
    };

    expect(mintingExports).toEqual([]);
    expect(Object.keys(packageJson.exports ?? {})).not.toContain('./invitation');
    await expect(access('src/modules/invitation/index.ts')).rejects.toMatchObject({
      code: 'ENOENT',
    });
  });

  it('retains data and storage compatibility types without service types', async () => {
    const rootSource = await readText('src/index.ts');
    const retainedTypes = [
      'AdminInvitation',
      'InvitationConfig',
      'InvitationStorage',
      'InvitationCreateRequest',
      'InvitationAcceptRequest',
    ];

    for (const retainedType of retainedTypes) {
      expect(rootSource).toMatch(new RegExp(`\\b${retainedType}\\b`));
    }

    expect(rootSource).not.toMatch(
      /\b(?:InvitationService|InvitationServiceConfig|CreateInvitationOptions|CreateInvitationResult)\b/,
    );
  });

  it('keeps invitation acceptance out of the auth MVP and documents the real boundary', async () => {
    const example = await readText('examples/tinyland-databaseless-auth-mvp.ts');
    const mvpDoc = await readText('docs/tinyland-databaseless-auth-mvp.md');
    const readme = await readText('README.md');
    const normalizedMvpDoc = mvpDoc.replace(/\s+/g, ' ');

    expect(example).not.toMatch(/invitation|invite|invited/i);
    expect(mvpDoc).toContain('`@tummycrypt/tinyland-invitation >=0.2.4`');
    expect(normalizedMvpDoc).toContain('downstream clean-consumer integration');
    expect(mvpDoc).toContain('PR #10');
    expect(mvpDoc).toContain('cross-process or cross-replica compare-and-set');
    expect(readme).toContain('version `>=0.2.4`');
    expect(readme).toContain('type-only `AdminInvitation`, `InvitationConfig`, `InvitationStorage`');
  });
});
