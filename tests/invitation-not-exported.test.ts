import { readFile } from 'node:fs/promises';
import { describe, expect, it } from 'vitest';
import * as pkg from '../src/index.js';

// TIN-2780: tinyland-auth's local InvitationService.createInvitation performs NO
// role authorization (options.role flows straight into the minted invite). The
// authoritative, fail-closed invite flow is the standalone
// @tummycrypt/tinyland-invitation package (TIN-1607, tinyland.dev PR #649).
//
// This guard asserts the ungated duplicate can never be reached from the package
// public surface, so a fresh consumer cannot shelf-grab a role-bearing invite
// minter that skips the authorization check.
describe('invitation service is not on the public surface (TIN-2780)', () => {
  const readText = (path: string) => readFile(path, 'utf8');

  it('does not export InvitationService or its factory from the package index', () => {
    const surface = pkg as Record<string, unknown>;
    expect(surface.InvitationService).toBeUndefined();
    expect(surface.createInvitationService).toBeUndefined();
  });

  it('exposes no exported factory that mints an invite without an authorization check', () => {
    // Any exported callable whose name hints at invitation minting would be a
    // regression: the only sanctioned minter is the standalone fail-closed
    // package. Assert none exist on the public surface.
    const mintingLikeExports = Object.keys(pkg as Record<string, unknown>).filter(
      (name) => /invit/i.test(name) && /(create|service|invite)/i.test(name),
    );
    expect(mintingLikeExports).toEqual([]);
  });

  it('re-adds no ./invitation subpath and no local re-export (source guards)', async () => {
    const packageJson = JSON.parse(await readText('package.json')) as {
      exports: Record<string, unknown>;
    };
    expect(Object.keys(packageJson.exports)).not.toContain('./invitation');

    const indexSource = await readText('src/index.ts');
    // The local invitation module must not be re-exported from the public index.
    expect(indexSource).not.toMatch(/export\s*\{[^}]*}\s*from\s*['"]\.\/modules\/invitation\/index\.js['"]/s);
  });
});
