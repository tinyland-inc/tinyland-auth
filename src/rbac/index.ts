import {
  ADMIN_ROLES,
  ROLE_HIERARCHY,
  isValidAdminRole,
  resolveCanonicalRole,
  type AdminRole,
} from '../types/auth.js';
import {
  PERMISSIONS,
  ROLE_CHARTER,
  ROLE_PERMISSIONS,
} from '../types/permissions.js';

export const RBAC_AUTHORITY_VERSION = 'tinyland-rbac/1' as const;

/**
 * Versioned role, rank, and capability authority shared by auth consumers.
 * Every referenced value is frozen at its declaration site.
 */
export const RBAC_AUTHORITY = Object.freeze({
  version: RBAC_AUTHORITY_VERSION,
  roles: ADMIN_ROLES,
  hierarchy: ROLE_HIERARCHY,
  permissions: ROLE_PERMISSIONS,
  permissionRegistry: PERMISSIONS,
  charter: ROLE_CHARTER,
});

const ROLE_TRANSLATION_CONTRACT = Symbol('tinyland-role-translation-contract');
const ROLE_TRANSLATION_CONTRACTS = new WeakSet<object>();

export interface RoleTranslationContract<ExternalRole extends string = string> {
  readonly authorityVersion: typeof RBAC_AUTHORITY_VERSION;
  readonly source: string;
  readonly roles: Readonly<Record<ExternalRole, AdminRole | null>>;
  readonly [ROLE_TRANSLATION_CONTRACT]: true;
}

function hasOwn(value: object, key: PropertyKey): boolean {
  return Object.prototype.hasOwnProperty.call(value, key);
}

export function createRoleTranslationContract<ExternalRole extends string>(
  source: string,
  roles: Readonly<Record<ExternalRole, AdminRole | null>>,
): RoleTranslationContract<ExternalRole> {
  if (!source.trim()) {
    throw new Error('role translation source is required');
  }

  const copiedRoles = Object.create(null) as Record<string, AdminRole | null>;
  for (const [role, target] of Object.entries(roles) as Array<[string, unknown]>) {
    if (
      target !== null &&
      (typeof target !== 'string' || !isValidAdminRole(target))
    ) {
      throw new Error(`invalid canonical role mapping for ${role}`);
    }
    copiedRoles[role] = target;
  }

  const contract = {
    authorityVersion: RBAC_AUTHORITY_VERSION,
    source,
    roles: Object.freeze(copiedRoles),
  } as unknown as RoleTranslationContract<ExternalRole>;
  Object.defineProperty(contract, ROLE_TRANSLATION_CONTRACT, {
    value: true,
    enumerable: false,
    configurable: false,
    writable: false,
  });
  Object.freeze(contract);
  ROLE_TRANSLATION_CONTRACTS.add(contract);
  return contract;
}

function isRoleTranslationContract(
  value: unknown,
): value is RoleTranslationContract<string> {
  if (typeof value !== 'object' || value === null) {
    return false;
  }

  const candidate = value as Record<PropertyKey, unknown>;
  return (
    ROLE_TRANSLATION_CONTRACTS.has(value) &&
    hasOwn(candidate, ROLE_TRANSLATION_CONTRACT) &&
    candidate[ROLE_TRANSLATION_CONTRACT] === true &&
    hasOwn(candidate, 'authorityVersion') &&
    candidate.authorityVersion === RBAC_AUTHORITY_VERSION &&
    hasOwn(candidate, 'source') &&
    typeof candidate.source === 'string' &&
    candidate.source.length > 0 &&
    hasOwn(candidate, 'roles') &&
    typeof candidate.roles === 'object' &&
    candidate.roles !== null &&
    Object.isFrozen(candidate) &&
    Object.isFrozen(candidate.roles)
  );
}

/**
 * Resolve a strict canonical role, or resolve exclusively through an explicit
 * consumer-local translation contract when one is supplied. Translation mode
 * deliberately permits source-name collisions such as a realm-local `viewer`;
 * it never falls back to canonical spelling for an unmapped source role.
 */
export function resolveRole<ExternalRole extends string = string>(
  role: AdminRole | ExternalRole | string,
  translation?: RoleTranslationContract<ExternalRole>,
): AdminRole | null {
  if (!translation) {
    return resolveCanonicalRole(role);
  }

  if (!isRoleTranslationContract(translation) || !hasOwn(translation.roles, role)) {
    return null;
  }

  const mapped = translation.roles[role as ExternalRole];
  return typeof mapped === 'string' && isValidAdminRole(mapped) ? mapped : null;
}

export function canManageResolvedRole<ExternalRole extends string = string>(
  actorRole: AdminRole | ExternalRole | string,
  targetRole: AdminRole | ExternalRole | string,
  translation?: RoleTranslationContract<ExternalRole>,
): boolean {
  const actor = resolveRole(actorRole, translation);
  const target = resolveRole(targetRole, translation);

  if (!actor || !target) {
    return false;
  }

  return ROLE_HIERARCHY[actor] > ROLE_HIERARCHY[target];
}
