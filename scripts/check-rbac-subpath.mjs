import assert from 'node:assert/strict';

const {
  RBAC_AUTHORITY,
  RBAC_AUTHORITY_VERSION,
  canManageResolvedRole,
} = await import('@tummycrypt/tinyland-auth/rbac');

assert.equal(RBAC_AUTHORITY.version, RBAC_AUTHORITY_VERSION);
assert.equal(canManageResolvedRole('admin', 'viewer'), true);
assert.equal(canManageResolvedRole('viewer', 'admin'), false);
assert.equal(Object.isFrozen(RBAC_AUTHORITY.permissions), true);
assert.equal(Object.isFrozen(RBAC_AUTHORITY.permissions.viewer), true);
assert.equal(Object.isFrozen(RBAC_AUTHORITY.charter.viewer), true);

assert.throws(() => {
  RBAC_AUTHORITY.permissions.viewer.push('admin.security.manage');
}, TypeError);
assert.throws(() => {
  RBAC_AUTHORITY.charter.viewer.rank = 100;
}, TypeError);

console.log(`RBAC package subpath verified at ${RBAC_AUTHORITY_VERSION}`);
