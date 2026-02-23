








import type { AdminRole, AdminUser } from '../../types/auth.js';
import { PERMISSIONS, ROLE_PERMISSIONS, type ContentVisibility } from '../../types/permissions.js';








export function getRolePermissions(role: AdminRole | string): string[] {
  const normalizedRole = role as AdminRole;
  return ROLE_PERMISSIONS[normalizedRole] || [PERMISSIONS.ADMIN_ACCESS];
}




export function hasPermission(user: AdminUser, permission: string): boolean {
  if (user.role === 'super_admin') {
    return true;
  }
  if (user.permissions?.includes(permission)) {
    return true;
  }
  const rolePermissions = getRolePermissions(user.role);
  return rolePermissions.includes(permission);
}




export function hasAnyPermission(user: AdminUser, permissions: string[]): boolean {
  return permissions.some(permission => hasPermission(user, permission));
}




export function hasAllPermissions(user: AdminUser, permissions: string[]): boolean {
  return permissions.every(permission => hasPermission(user, permission));
}




export function requirePermission(user: AdminUser, permission: string): void {
  if (!hasPermission(user, permission)) {
    throw new Error(`Permission denied: ${permission} required`);
  }
}




export function requireAnyPermission(user: AdminUser, permissions: string[]): void {
  if (!hasAnyPermission(user, permissions)) {
    throw new Error(`Permission denied: one of [${permissions.join(', ')}] required`);
  }
}




export function requireAllPermissions(user: AdminUser, permissions: string[]): void {
  if (!hasAllPermissions(user, permissions)) {
    throw new Error(`Permission denied: all of [${permissions.join(', ')}] required`);
  }
}




export function getUserPermissions(user: AdminUser): string[] {
  if (user.role === 'super_admin') {
    return Object.values(PERMISSIONS);
  }
  const rolePerms = getRolePermissions(user.role);
  const userPerms = user.permissions || [];
  return [...new Set([...rolePerms, ...userPerms])];
}




export function canManageRole(actorRole: AdminRole | string, targetRole: AdminRole | string): boolean {
  const normalizeRole = (role: AdminRole | string): string => {
    return String(role).toLowerCase().replace(/-/g, '_');
  };

  const normalizedActor = normalizeRole(actorRole);
  const normalizedTarget = normalizeRole(targetRole);

  const roleHierarchy = [
    'super_admin',
    'admin',
    'editor',
    'event_manager',
    'moderator',
    'contributor',
    'member',
    'viewer',
  ];

  const actorIndex = roleHierarchy.indexOf(normalizedActor);
  const targetIndex = roleHierarchy.indexOf(normalizedTarget);

  if (actorIndex === -1 || targetIndex === -1) {
    return false;
  }

  return actorIndex < targetIndex;
}




export function isValidPermission(permission: string): boolean {
  return Object.values(PERMISSIONS).includes(permission as typeof PERMISSIONS[keyof typeof PERMISSIONS]);
}




export function getPermissionDisplayName(permission: string): string {
  const displayNames: Record<string, string> = {
    [PERMISSIONS.ADMIN_ACCESS]: 'Admin Panel Access',
    [PERMISSIONS.ADMIN_USERS_VIEW]: 'View Users',
    [PERMISSIONS.ADMIN_USERS_MANAGE]: 'Manage Users',
    [PERMISSIONS.ADMIN_USERS_DELETE]: 'Delete Users',
    [PERMISSIONS.ADMIN_CONTENT_VIEW]: 'View Content',
    [PERMISSIONS.ADMIN_CONTENT_MANAGE]: 'Manage Content',
    [PERMISSIONS.ADMIN_CONTENT_MODERATE]: 'Moderate Content',
    [PERMISSIONS.ADMIN_EVENTS_VIEW]: 'View Events',
    [PERMISSIONS.ADMIN_EVENTS_MANAGE]: 'Manage Events',
    [PERMISSIONS.ADMIN_ANALYTICS_VIEW]: 'View Analytics',
    [PERMISSIONS.ADMIN_ANALYTICS_EXPORT]: 'Export Analytics',
    [PERMISSIONS.ADMIN_SETTINGS_VIEW]: 'View Settings',
    [PERMISSIONS.ADMIN_SETTINGS_MANAGE]: 'Manage Settings',
    [PERMISSIONS.ADMIN_SECURITY_VIEW]: 'View Security',
    [PERMISSIONS.ADMIN_SECURITY_MANAGE]: 'Manage Security',
    [PERMISSIONS.ADMIN_LOGS_VIEW]: 'View Logs',
    [PERMISSIONS.ADMIN_LOGS_EXPORT]: 'Export Logs',
  };
  return displayNames[permission] || permission;
}





const ALL_ROLES = ['super_admin', 'admin', 'editor', 'moderator', 'event_manager', 'contributor', 'member', 'viewer'];
const CONTENT_CREATORS = ['super_admin', 'admin', 'editor', 'moderator', 'event_manager', 'contributor', 'member'];
const EDITORS = ['super_admin', 'admin', 'editor'];
const ADMINS = ['super_admin', 'admin'];
const SUPER_ADMIN = ['super_admin'];

function normalizeRole(role: AdminRole | string): string {
  return String(role).toLowerCase().replace(/-/g, '_');
}


export function canViewPosts(role: AdminRole | string): boolean {
  return ALL_ROLES.includes(normalizeRole(role));
}

export function canCreatePosts(role: AdminRole | string): boolean {
  return CONTENT_CREATORS.includes(normalizeRole(role));
}

export function canEditPosts(role: AdminRole | string): boolean {
  return EDITORS.includes(normalizeRole(role));
}

export function canDeletePosts(role: AdminRole | string): boolean {
  return ADMINS.includes(normalizeRole(role));
}


export function canViewEvents(role: AdminRole | string): boolean {
  return ALL_ROLES.includes(normalizeRole(role));
}

export function canCreateEvents(role: AdminRole | string): boolean {
  const r = normalizeRole(role);
  return ['super_admin', 'admin', 'event_manager', 'member'].includes(r);
}

export function canEditEvents(role: AdminRole | string): boolean {
  const r = normalizeRole(role);
  return ['super_admin', 'admin', 'event_manager'].includes(r);
}

export function canDeleteEvents(role: AdminRole | string): boolean {
  return ADMINS.includes(normalizeRole(role));
}


export function canViewProfiles(role: AdminRole | string): boolean {
  return ALL_ROLES.includes(normalizeRole(role));
}

export function canCreateProfiles(role: AdminRole | string): boolean {
  return ADMINS.includes(normalizeRole(role));
}

export function canEditOwnProfile(role: AdminRole | string): boolean {
  return ALL_ROLES.includes(normalizeRole(role));
}

export function canEditAnyProfile(role: AdminRole | string): boolean {
  return ADMINS.includes(normalizeRole(role));
}

export function canDeleteProfiles(role: AdminRole | string): boolean {
  return SUPER_ADMIN.includes(normalizeRole(role));
}


export function canViewUsers(role: AdminRole | string): boolean {
  const r = normalizeRole(role);
  return ['super_admin', 'admin', 'moderator'].includes(r);
}

export function canManageUsers(role: AdminRole | string): boolean {
  return ADMINS.includes(normalizeRole(role));
}


export function canViewVideos(role: AdminRole | string): boolean {
  return ALL_ROLES.includes(normalizeRole(role));
}

export function canCreateVideos(role: AdminRole | string): boolean {
  const r = normalizeRole(role);
  return ['super_admin', 'admin', 'editor', 'contributor'].includes(r);
}

export function canEditVideos(role: AdminRole | string): boolean {
  return EDITORS.includes(normalizeRole(role));
}

export function canDeleteVideos(role: AdminRole | string): boolean {
  return ADMINS.includes(normalizeRole(role));
}





export function canCreatePublicContent(role: AdminRole | string): boolean {
  const r = normalizeRole(role);
  return ['super_admin', 'admin', 'editor', 'moderator', 'event_manager', 'contributor'].includes(r);
}

export function canCreateMemberOnlyContent(role: AdminRole | string): boolean {
  return CONTENT_CREATORS.includes(normalizeRole(role));
}

export function canFeatureProfile(role: AdminRole | string): boolean {
  return ADMINS.includes(normalizeRole(role));
}

export function canEditOwnContent(role: AdminRole | string): boolean {
  return CONTENT_CREATORS.includes(normalizeRole(role));
}

export function canDeleteOwnContent(role: AdminRole | string): boolean {
  const r = normalizeRole(role);
  return ['super_admin', 'admin', 'editor', 'event_manager', 'contributor', 'member'].includes(r);
}

export function canEditContent(role: AdminRole | string): boolean {
  const r = normalizeRole(role);
  return ['super_admin', 'admin', 'editor', 'moderator'].includes(r);
}

export function canDeleteContent(role: AdminRole | string): boolean {
  return ADMINS.includes(normalizeRole(role));
}

export function isMemberRole(role: AdminRole | string): boolean {
  return normalizeRole(role) === 'member';
}

export function canViewMemberOnlyContent(role: AdminRole | string): boolean {
  return CONTENT_CREATORS.includes(normalizeRole(role));
}

export function getAllowedVisibilityOptions(role: AdminRole | string): string[] {
  const r = normalizeRole(role);

  if (ADMINS.includes(r)) {
    return ['public', 'members', 'admin', 'private'];
  }

  if (['editor', 'moderator', 'event_manager', 'contributor'].includes(r)) {
    return ['public', 'members', 'private'];
  }

  if (r === 'member') {
    return ['members', 'private'];
  }

  return [];
}








export function canViewContent(
  visibility: ContentVisibility | string | undefined,
  userRole: AdminRole | string | null | undefined,
  authorId?: string | null,
  userId?: string | null
): boolean {
  const v = (visibility || 'public').toLowerCase();

  if (v === 'public') {
    return true;
  }

  if (!userRole) {
    return false;
  }

  const r = normalizeRole(userRole);

  if (r === 'super_admin') {
    return true;
  }

  if (v === 'private') {
    return userId != null && authorId != null && userId === authorId;
  }

  if (v === 'admin') {
    return ['admin', 'editor', 'moderator', 'event_manager'].includes(r);
  }

  if (v === 'members') {
    return ['admin', 'editor', 'moderator', 'event_manager', 'contributor', 'member'].includes(r);
  }

  return false;
}




export function filterContentByVisibility<T extends { visibility?: string; authorId?: string }>(
  items: T[],
  userRole: AdminRole | string | null | undefined,
  userId?: string | null
): T[] {
  return items.filter(item =>
    canViewContent(item.visibility, userRole, item.authorId, userId)
  );
}





export {
  isContentOwner,
  canEditContent as canEditOwnedContent,
  canDeleteContent as canDeleteOwnedContent,
  requireContentEditPermission,
  requireContentDeletePermission,
  isSoleOwner,
  type OwnershipUser,
  type OwnedContent,
  type OwnershipError,
} from './ownership.js';





export { PERMISSIONS, ROLE_PERMISSIONS } from '../../types/permissions.js';
