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

  it('points package-owned examples and docs to tinyland-invitation', async () => {
    const example = await readText('examples/tinyland-databaseless-auth-mvp.ts');
    const mvpDoc = await readText('docs/tinyland-databaseless-auth-mvp.md');
    const readme = await readText('README.md');

    expect(example).not.toMatch(/\bcreateInvitationService\b/);
    expect(example).toContain("authority: '@tummycrypt/tinyland-invitation'");
    expect(mvpDoc).toContain('`@tummycrypt/tinyland-invitation`');
    expect(readme).toContain(
      'Use `@tummycrypt/tinyland-invitation` for fail-closed invitation authorization',
    );
  });
});
