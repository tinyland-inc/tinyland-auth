import { describe, expect, it } from 'vitest';
import {
  ADMIN_ROLES,
  PERMISSIONS,
  RBAC_AUTHORITY,
  RBAC_AUTHORITY_VERSION,
  ROLE_HIERARCHY,
  ROLE_PERMISSIONS,
  canManageResolvedRole,
  canManageRole,
  createRoleTranslationContract,
  getRolePermissions,
  getUserPermissions,
  hasAllPermissions,
  hasEqualOrHigherRole,
  hasHigherRole,
  hasPermission,
  isAdminUser,
  requireAllPermissions,
  resolveCanonicalRole,
  resolveRole,
  type AdminRole,
  type AdminUser,
  type RoleTranslationContract,
} from '../src/index.js';

function user(role: string, permissions?: string[]): AdminUser {
  return {
    id: 'rbac-user',
    handle: 'rbac-user',
    passwordHash: 'not-used',
    totpEnabled: true,
    role: role as AdminRole,
    permissions,
    isActive: true,
    needsOnboarding: false,
    onboardingStep: 0,
    createdAt: '2026-07-13T00:00:00.000Z',
    updatedAt: '2026-07-13T00:00:00.000Z',
  };
}

describe('versioned RBAC authority', () => {
  it('publishes one frozen role, rank, and capability contract', () => {
    expect(RBAC_AUTHORITY.version).toBe(RBAC_AUTHORITY_VERSION);
    expect(RBAC_AUTHORITY.roles).toBe(ADMIN_ROLES);
    expect(RBAC_AUTHORITY.hierarchy).toBe(ROLE_HIERARCHY);
    expect(RBAC_AUTHORITY.permissions).toBe(ROLE_PERMISSIONS);
    expect(Object.isFrozen(RBAC_AUTHORITY)).toBe(true);
    expect(Object.isFrozen(ADMIN_ROLES)).toBe(true);
    expect(Object.isFrozen(ROLE_HIERARCHY)).toBe(true);
    expect(Object.isFrozen(ROLE_PERMISSIONS)).toBe(true);
    for (const role of ADMIN_ROLES) {
      expect(Object.isFrozen(ROLE_PERMISSIONS[role])).toBe(true);
      expect(Object.isFrozen(RBAC_AUTHORITY.charter[role])).toBe(true);
    }
  });

  it('makes every canonical management decision from the same rank table', () => {
    for (const actor of ADMIN_ROLES) {
      for (const target of ADMIN_ROLES) {
        const expected = ROLE_HIERARCHY[actor] > ROLE_HIERARCHY[target];
        expect(canManageRole(actor, target)).toBe(expected);
        expect(canManageResolvedRole(actor, target)).toBe(expected);
      }
    }
  });
});

describe('role resolution and translation', () => {
  const translation = createRoleTranslationContract(
    'test-local-roles/v1',
    {
      local_owner: 'admin',
      local_staff: 'member',
    },
  );

  it('accepts only exact canonical spelling without a translation contract', () => {
    expect(resolveCanonicalRole('super_admin')).toBe('super_admin');
    expect(resolveCanonicalRole('SUPER-ADMIN')).toBeNull();
    expect(resolveRole('event-manager')).toBeNull();
  });

  it('resolves only explicit, current-version local mappings', () => {
    expect(resolveRole('local_owner', translation)).toBe('admin');
    expect(resolveRole('local_staff', translation)).toBe('member');
    expect(resolveRole('unmapped', translation)).toBeNull();

    const stale = {
      ...translation,
      authorityVersion: 'tinyland-rbac/0',
    } as unknown as RoleTranslationContract<string>;
    expect(resolveRole('local_owner', stale)).toBeNull();
  });

  it('uses explicit translation mode for source-name collisions', () => {
    const reviewRealm = createRoleTranslationContract('review-realm/v1', {
      viewer: null,
      admin: 'viewer',
    });
    expect(resolveRole('viewer')).toBe('viewer');
    expect(resolveRole('viewer', reviewRealm)).toBeNull();
    expect(resolveRole('admin', reviewRealm)).toBe('viewer');

    const inheritedContract = Object.create({
      authorityVersion: RBAC_AUTHORITY_VERSION,
      source: 'inherited/v1',
      roles: { local_owner: 'admin' },
    }) as RoleTranslationContract<string>;
    expect(resolveRole('local_owner', inheritedContract)).toBeNull();
  });

  it('copies and freezes reviewed mappings', () => {
    const sourceRoles: Record<'local_owner', AdminRole | null> = {
      local_owner: 'admin',
    };
    const contract = createRoleTranslationContract('mutable-input/v1', sourceRoles);
    sourceRoles.local_owner = 'super_admin';

    expect(resolveRole('local_owner', contract)).toBe('admin');
    expect(Object.isFrozen(contract)).toBe(true);
    expect(Object.isFrozen(contract.roles)).toBe(true);
    expect(() => {
      (contract.roles as Record<string, AdminRole | null>).local_owner = 'super_admin';
    }).toThrow();
  });

  it('rejects frozen spread clones with accessor-backed authority', () => {
    let target: AdminRole = 'member';
    const accessorRoles = {} as Record<string, AdminRole | null>;
    Object.defineProperty(accessorRoles, 'local_owner', {
      enumerable: true,
      get: () => target,
    });
    Object.freeze(accessorRoles);

    const forged = Object.freeze({
      ...translation,
      roles: accessorRoles,
    }) as RoleTranslationContract<string>;
    expect(resolveRole('local_owner', forged)).toBeNull();
    target = 'super_admin';
    expect(resolveRole('local_owner', forged)).toBeNull();
  });

  it('rejects forged contracts, invalid targets, and unmapped actors', () => {
    const invalid = {
      authorityVersion: RBAC_AUTHORITY_VERSION,
      source: 'forged/v1',
      roles: { local_owner: 'root' },
    } as unknown as RoleTranslationContract<string>;
    expect(resolveRole('local_owner', invalid)).toBeNull();
    expect(() => createRoleTranslationContract('invalid/v1', {
      local_owner: 'super-admin' as AdminRole,
    })).toThrow('invalid canonical role mapping');
    const missingRoles = {
      authorityVersion: RBAC_AUTHORITY_VERSION,
      source: 'forged/v1',
      roles: null,
    } as unknown as RoleTranslationContract<string>;
    expect(resolveRole('local_owner', missingRoles)).toBeNull();
    expect(canManageResolvedRole('local_owner', 'local_staff', translation)).toBe(true);
    expect(canManageResolvedRole('local_staff', 'local_owner', translation)).toBe(false);
    expect(canManageResolvedRole('unmapped', 'local_staff', translation)).toBe(false);
  });
});

describe('fail-closed permission and rank boundaries', () => {
  const unknownRoles = [
    '',
    'owner',
    'SUPER-ADMIN',
    'super-admin',
    'constructor',
    'toString',
    '__proto__',
  ];

  it.each(unknownRoles)('denies unknown role %j without throwing', (role) => {
    expect(getRolePermissions(role)).toEqual([]);
    expect(getUserPermissions(user(role, [PERMISSIONS.ADMIN_SECURITY_MANAGE]))).toEqual([]);
    expect(hasPermission(user(role, [PERMISSIONS.ADMIN_ACCESS]), PERMISSIONS.ADMIN_ACCESS)).toBe(false);
    expect(hasHigherRole(role, 'viewer')).toBe(false);
    expect(hasEqualOrHigherRole(role, 'viewer')).toBe(false);
    expect(canManageRole(role, 'viewer')).toBe(false);
  });

  it('preserves explicit grants only for valid roles', () => {
    expect(hasPermission(user('viewer', [PERMISSIONS.ADMIN_USERS_VIEW]), PERMISSIONS.ADMIN_USERS_VIEW)).toBe(true);
  });

  it('returns a detached permission row', () => {
    const permissions = getRolePermissions('viewer');
    permissions.push(PERMISSIONS.ADMIN_SECURITY_MANAGE);
    expect(ROLE_PERMISSIONS.viewer).not.toContain(PERMISSIONS.ADMIN_SECURITY_MANAGE);
  });

  it('denies an empty all-permissions boundary', () => {
    expect(hasAllPermissions(user('admin'), [])).toBe(false);
    expect(() => requireAllPermissions(user('admin'), [])).toThrow('Permission denied');
  });

  it('rejects an otherwise shaped user with an unknown role', () => {
    expect(isAdminUser(user('owner'))).toBe(false);
    expect(isAdminUser(user('admin'))).toBe(true);
  });
});
