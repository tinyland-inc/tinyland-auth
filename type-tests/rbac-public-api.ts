import {
  RBAC_AUTHORITY,
  canManageResolvedRole,
} from '@tummycrypt/tinyland-auth/rbac';

const canManageViewer: boolean = canManageResolvedRole('admin', 'viewer');
const viewerPermissions: readonly string[] = RBAC_AUTHORITY.permissions.viewer;
const viewerRank: number = RBAC_AUTHORITY.charter.viewer.rank;

void canManageViewer;
void viewerPermissions;
void viewerRank;

// @ts-expect-error Frozen authority rows must reject mutation in consumer code.
RBAC_AUTHORITY.permissions.viewer.push('admin.security.manage');
// @ts-expect-error Frozen authority records must reject row replacement.
RBAC_AUTHORITY.permissions.viewer = [];
// @ts-expect-error Frozen charter entries must reject field mutation.
RBAC_AUTHORITY.charter.viewer.rank = 100;
// @ts-expect-error Frozen permission registry entries must reject replacement.
RBAC_AUTHORITY.permissionRegistry.ADMIN_ACCESS = 'admin.access';
