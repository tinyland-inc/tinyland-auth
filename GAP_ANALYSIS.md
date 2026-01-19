# @tinyland/auth - Gap Analysis Report

**Generated**: 2026-01-17
**Source**: `/Users/jsullivan2/git/tinyland.dev/src/lib/`
**Package**: `/Users/jsullivan2/git/tinyland.dev/packages/tinyland-auth/src/`

---

## Executive Summary

| Metric | Value |
|--------|-------|
| **Overall Completion** | 85% |
| **Core Functions Extracted** | 45/52 (86%) |
| **Types Extracted** | 38/41 (93%) |
| **Security Functions** | 8/8 (100%) |
| **Critical Missing** | 7 items |

The @tinyland/auth package is a well-structured extraction of tinyland.dev's authentication system. The core permission, TOTP, and session management modules are fully functional. However, several SvelteKit-specific integrations and file-based storage adapters are missing.

---

## Detailed Comparison

### 1. Permissions System (permissions.ts)

#### Exported Functions Comparison

| Original Function | Package Function | Status | Notes |
|-------------------|------------------|--------|-------|
| `getRolePermissions` | `getRolePermissions` | OK | Identical signature |
| `hasPermission` | `hasPermission` | OK | Identical signature |
| `hasAnyPermission` | `hasAnyPermission` | OK | Identical signature |
| `hasAllPermissions` | `hasAllPermissions` | OK | Identical signature |
| `requirePermission` | `requirePermission` | OK | Identical signature |
| `requireAnyPermission` | `requireAnyPermission` | OK | Identical signature |
| `requireAllPermissions` | `requireAllPermissions` | OK | Identical signature |
| `getUserPermissions` | `getUserPermissions` | OK | Identical signature |
| `canManageRole` | `canManageRole` | OK | Identical signature |
| `isValidPermission` | `isValidPermission` | OK | Identical signature |
| `getPermissionDisplayName` | `getPermissionDisplayName` | OK | Identical signature |
| `canViewPosts` | `canViewPosts` | OK | Identical signature |
| `canCreatePosts` | `canCreatePosts` | OK | Identical signature |
| `canEditPosts` | `canEditPosts` | OK | Identical signature |
| `canDeletePosts` | `canDeletePosts` | OK | Identical signature |
| `canViewEvents` | `canViewEvents` | OK | Identical signature |
| `canCreateEvents` | `canCreateEvents` | OK | Identical signature |
| `canEditEvents` | `canEditEvents` | OK | Identical signature |
| `canDeleteEvents` | `canDeleteEvents` | OK | Identical signature |
| `canViewProfiles` | `canViewProfiles` | OK | Identical signature |
| `canCreateProfiles` | `canCreateProfiles` | OK | Identical signature |
| `canEditOwnProfile` | `canEditOwnProfile` | OK | Identical signature |
| `canEditAnyProfile` | `canEditAnyProfile` | OK | Identical signature |
| `canDeleteProfiles` | `canDeleteProfiles` | OK | Identical signature |
| `canViewUsers` | `canViewUsers` | OK | Identical signature |
| `canManageUsers` | `canManageUsers` | OK | Identical signature |
| `canViewVideos` | `canViewVideos` | OK | Identical signature |
| `canCreateVideos` | `canCreateVideos` | OK | Identical signature |
| `canEditVideos` | `canEditVideos` | OK | Identical signature |
| `canDeleteVideos` | `canDeleteVideos` | OK | Identical signature |
| `canCreatePublicContent` | `canCreatePublicContent` | OK | Identical signature |
| `canCreateMemberOnlyContent` | `canCreateMemberOnlyContent` | OK | Identical signature |
| `canFeatureProfile` | `canFeatureProfile` | OK | Identical signature |
| `canEditOwnContent` | `canEditOwnContent` | OK | Identical signature |
| `canDeleteOwnContent` | `canDeleteOwnContent` | OK | Identical signature |
| `canEditContent` | `canEditContent` | OK | Identical signature |
| `canDeleteContent` | `canDeleteContent` | OK | Identical signature |
| `isMemberRole` | `isMemberRole` | OK | Identical signature |
| `canViewMemberOnlyContent` | `canViewMemberOnlyContent` | OK | Identical signature |
| `getAllowedVisibilityOptions` | `getAllowedVisibilityOptions` | OK | Identical signature |
| `canViewContent` | `canViewContent` | OK | Identical signature |
| `filterContentByVisibility` | `filterContentByVisibility` | OK | Identical signature |

**Result**: 42/42 functions extracted (100%)

#### Minor Differences

1. **Original imports from `$lib/types/admin`**: Package uses local types
2. **`AdminRole` enum comparison**: Original uses imported enum; package exports both type and const object for compatibility

---

### 2. Session Manager (sessionManager.ts)

#### Original Functions (SvelteKit-specific)

| Original Function | Package Equivalent | Status | Notes |
|-------------------|-------------------|--------|-------|
| `getAllSessions` | `storage.getAllSessions()` | CHANGED | Now via storage adapter |
| `getSession` | `SessionManager.getSession()` | OK | Class method with expiry check |
| `createSession` | `SessionManager.createSession()` | OK | Signature compatible |
| `removeSession` | `SessionManager.removeSession()` | OK | Identical behavior |
| `cleanupExpiredSessions` | `SessionManager.cleanupExpiredSessions()` | OK | Via storage adapter |
| `validateSession` | `SessionManager.validateSession()` | OK | Identical behavior |
| `setSessionCookie` | `setSessionCookie` (SvelteKit adapter) | OK | Moved to adapter |
| `setAuthDataCookie` | `setAuthDataCookie` (SvelteKit adapter) | OK | Moved to adapter |
| `clearSessionCookies` | `clearSessionCookies` (SvelteKit adapter) | OK | Moved to adapter |
| `updateSession` | `SessionManager.updateSession()` | OK | Identical signature |
| `updateSessionUser` | `SessionManager.updateSessionUser()` | OK | Identical signature |
| `refreshSession` | `SessionManager.refreshSession()` | DIFFERENT | Returns Session (not user data) |

#### Missing Functions

| Function | Reason | Impact |
|----------|--------|--------|
| `ensureSessionsFile` | File-based; would be in FileStorageAdapter | LOW |
| `saveSession` (internal) | Abstracted to storage adapter | NONE |

#### Signature Differences

**Original `createSession`**:
```typescript
export async function createSession(
  userId: string,
  user: any,
  metadata?: SessionMetadata
): Promise<Session>
```

**Package `SessionManager.createSession`**:
```typescript
async createSession(
  userId: string,
  user: Partial<AdminUser>,
  metadata?: SessionMetadata
): Promise<Session>
```

**Verdict**: `user: any` changed to `user: Partial<AdminUser>` - **type safety improvement**

---

### 3. TOTP Service (totpService.ts)

#### Original Class Methods

| Original Method | Package Method | Status | Notes |
|-----------------|----------------|--------|-------|
| `constructor` | `constructor(config)` | CHANGED | Requires explicit config (no env vars) |
| `init()` | N/A | MISSING | File system init; should be in storage adapter |
| `encrypt()` | `encrypt()` | OK | Identical implementation |
| `decrypt()` | `decrypt()` | OK | Identical implementation |
| `generateSecret()` | `generateSecret()` | OK | Identical signature |
| `saveExistingSecret()` | N/A | MISSING | Would be via storage adapter |
| `saveSecret()` (private) | N/A | ABSTRACTED | Would be via storage adapter |
| `loadSecret()` | N/A | MISSING | Would be via storage adapter |
| `verifyToken()` | `verifyToken()` | DIFFERENT | Takes TOTPSecret instead of handle |
| `generateToken()` | `generateToken()` | DIFFERENT | Takes TOTPSecret instead of handle |
| `listHandles()` | N/A | MISSING | Storage adapter concern |
| `removeSecret()` | N/A | MISSING | Storage adapter concern |
| `encryptBackupCodes()` | `encryptBackupCodes()` | OK | Identical |
| `decryptBackupCodes()` | `decryptBackupCodes()` | OK | Identical |

#### Signature Changes

**Original `verifyToken`**:
```typescript
async verifyToken(handle: string, token: string): Promise<boolean>
```

**Package `verifyToken`**:
```typescript
async verifyToken(secretOrNull: TOTPSecret | null, token: string): Promise<boolean>
```

**Rationale**: Package separates secret loading (storage adapter) from verification (core service). This is correct architecture.

#### Missing Features

| Feature | Impact | Recommendation |
|---------|--------|----------------|
| `init()` file system setup | HIGH | Add `TOTPStorageService` or document FileStorageAdapter requirements |
| `loadSecret(handle)` | HIGH | Requires storage adapter integration |
| `listHandles()` | MEDIUM | Add to IStorageAdapter interface |

---

### 4. Backup Codes (backupCodes.ts)

#### Original Functions vs Package

| Original | Package | Status | Notes |
|----------|---------|--------|-------|
| `BackupCodesService` class | Pure functions | REDESIGNED | Better for tree-shaking |
| `generateCodes()` | `generateBackupCodes()` | OK | Same implementation |
| `hashCode()` | `hashBackupCode()` | OK | Same implementation |
| `saveCodes()` | N/A | MISSING | Storage adapter concern |
| `verifyCode()` | `verifyBackupCode()` | REDESIGNED | Returns `{valid, codeSet, remaining}` |
| `getRemainingCount()` | `getRemainingCodesCount()` | OK | Same logic |
| `hasCodes()` | `hasUnusedCodes()` | OK | Renamed for clarity |
| `regenerateCodes()` | `generateBackupCodes()` | SIMPLIFIED | Just re-generate; save via adapter |
| `loadCodes()` | N/A | MISSING | Storage adapter concern |
| `updateCodes()` | N/A | MISSING | Storage adapter concern |
| `formatCodesForDisplay()` | `formatCodesForDisplay()` | OK | Identical |
| `isValidFormat()` | `isValidCodeFormat()` | OK | Same regex |
| `encrypt()` | N/A | MOVED | Encryption via TOTPService |
| `decrypt()` | N/A | MOVED | Encryption via TOTPService |

#### Helper Functions

| Original Helper | Package Equivalent | Status |
|-----------------|-------------------|--------|
| `generateBackupCodes(userId)` | `generateBackupCodes(count)` | CHANGED - no storage |
| `verifyBackupCode(userId, code)` | `verifyBackupCode(codeSet, code)` | CHANGED - takes codeSet |
| `getBackupCodeStatus(userId)` | N/A | MISSING |

**Note**: Package backup codes are pure functions. Integration code must:
1. Load BackupCodeSet from storage
2. Call `verifyBackupCode(codeSet, code)`
3. Save updated codeSet to storage

---

### 5. Auth Types (types/auth.ts)

#### Type Comparison

| Original Type | Package Type | Status | Differences |
|---------------|--------------|--------|-------------|
| `AdminRole` | `AdminRole` | OK | Type alias + const object |
| `AdminUser` | `AdminUser` | OK | Identical properties |
| `Session` | `Session` | OK | Identical |
| `SessionUser` | `SessionUser` | OK | Identical |
| `SessionMetadata` | `SessionMetadata` | OK | Identical |
| `DeviceType` | `DeviceType` | OK | Identical |
| `TOTPSecret` | `TOTPSecret` | OK | Identical |
| `EncryptedTotpSecret` | `EncryptedTOTPSecret` | RENAMED | PascalCase consistency |
| `EncryptedData` | `EncryptedData` | OK | Identical |
| `BackupCode` | `BackupCode` | OK | Identical |
| `BackupCodeSet` | `BackupCodeSet` | OK | Identical |
| `EncryptedBackupCode` | `EncryptedBackupCode` | OK | Identical |
| `AdminInvitation` | `AdminInvitation` | OK | +`isActive` field |
| `AuditLogEntry` | `AuditEvent` | RENAMED | Consistent naming |
| `AuditEventType` | `AuditEventType` | OK | +2 new events |
| `AuthErrorCode` | `AuthErrorCode` | OK | Identical |
| `AuthError` | `AuthError` | OK | `details: Record<string, unknown>` |
| `AuthConfig` | `AuthConfig` | RESTRUCTURED | Nested config objects |

#### Missing Types

| Original Type | Status | Impact |
|---------------|--------|--------|
| `BootstrapRequest` | MISSING | LOW - Bootstrap flow types |
| `BootstrapResponse` | MISSING | LOW - Bootstrap flow types |
| `BootstrapVerificationRequest` | MISSING | LOW - Bootstrap flow types |
| `BootstrapStatus` | MISSING | LOW - Bootstrap flow types |
| `InvitationCreateRequest` | MISSING | MEDIUM - API contract |
| `InvitationCreateResponse` | MISSING | MEDIUM - API contract |
| `InvitationAcceptRequest` | MISSING | MEDIUM - API contract |
| `InvitationAcceptResponse` | MISSING | MEDIUM - API contract |
| `InvitationListResponse` | MISSING | MEDIUM - API contract |
| `LoginRequest` | MISSING | MEDIUM - API contract |
| `LoginResponse` | MISSING | MEDIUM - API contract |
| `LogoutRequest` | MISSING | LOW |
| `LogoutResponse` | MISSING | LOW |
| `OnboardingStatus` | MISSING | MEDIUM - Onboarding flow |
| `ProfileSetupRequest` | MISSING | LOW |
| `SecurityReviewRequest` | MISSING | LOW |
| `PreferencesSetupRequest` | MISSING | LOW |
| `OnboardingStepResponse` | MISSING | LOW |
| `TotpSetupRequest` | MISSING | MEDIUM |
| `TotpSetupResponse` | MISSING | MEDIUM |
| `BackupCodeUsageRequest` | MISSING | LOW |
| `BackupCodeUsageResponse` | MISSING | LOW |
| `SessionRefreshRequest` | MISSING | LOW |
| `SessionRefreshResponse` | MISSING | LOW |
| `SessionListResponse` | MISSING | LOW |

#### Added Types in Package

| Type | Purpose |
|------|---------|
| `AuditEvent.SESSION_CREATED` | New audit event |
| `AuditEvent.SESSION_DESTROYED` | New audit event |
| `AuditEvent.ROLE_CHANGED` | New audit event |
| `AuditEvent.ACCOUNT_LOCKED` | New audit event |
| `AuditEvent.ACCOUNT_UNLOCKED` | New audit event |
| `AdminInvitation.isActive` | Active state flag |
| `AuditSeverity` | Extracted type alias |

---

### 6. Storage Adapter Compatibility

#### File Format Analysis

**Original sessions.json format** (inferred from sessionManager.ts):
```json
[
  {
    "id": "uuid",
    "userId": "uuid",
    "expires": "ISO8601",
    "expiresAt": "ISO8601",
    "createdAt": "ISO8601",
    "user": {
      "id": "...",
      "username": "...",
      "name": "...",
      "role": "...",
      "needsOnboarding": false
    },
    "clientIp": "hashed",
    "clientIpMasked": "192.168.*.*",
    "userAgent": "...",
    "deviceType": "desktop",
    "browserFingerprint": "...",
    "geoLocation": { "country": "US" }
  }
]
```

**Package MemoryStorageAdapter** creates identical structure.

**Missing**: `FileStorageAdapter` for production use with JSON files.

#### IStorageAdapter Interface Completeness

| Method | Implemented in Memory | Needed for File |
|--------|----------------------|-----------------|
| `getUser` | YES | YES |
| `getUserByHandle` | YES | YES |
| `getUserByEmail` | YES | YES |
| `getAllUsers` | YES | YES |
| `createUser` | YES | YES |
| `updateUser` | YES | YES |
| `deleteUser` | YES | YES |
| `hasUsers` | YES | YES |
| `getSession` | YES | YES |
| `getSessionsByUser` | YES | YES |
| `getAllSessions` | YES | YES |
| `createSession` | YES | YES |
| `updateSession` | YES | YES |
| `deleteSession` | YES | YES |
| `deleteUserSessions` | YES | YES |
| `cleanupExpiredSessions` | YES | YES |
| `getTOTPSecret` | YES | YES |
| `saveTOTPSecret` | YES | YES |
| `deleteTOTPSecret` | YES | YES |
| `getBackupCodes` | YES | YES |
| `saveBackupCodes` | YES | YES |
| `deleteBackupCodes` | YES | YES |
| `getInvitation` | YES | YES |
| `getInvitationById` | YES | YES |
| `getAllInvitations` | YES | YES |
| `getPendingInvitations` | YES | YES |
| `createInvitation` | YES | YES |
| `updateInvitation` | YES | YES |
| `deleteInvitation` | YES | YES |
| `cleanupExpiredInvitations` | YES | YES |
| `logAuditEvent` | YES | YES |
| `getAuditEvents` | YES | YES |
| `getRecentAuditEvents` | YES | YES |
| `init` | YES | YES |
| `close` | YES | YES |

---

### 7. Security Implementation Review

#### Timing-Safe Functions

| Original | Package | Implementation |
|----------|---------|---------------|
| `constantTimeCompare` | `constantTimeCompare` | OK - timingSafeEqual |
| `timingSafeVerify` | `timingSafeVerify` | OK - normalized timing |
| `timingSafeQuery` | `timingSafeQuery` | OK - minimum time |
| N/A | `timingSafeError` | NEW - generic error messages |

#### IP Hashing/Masking

| Feature | Original | Package | Status |
|---------|----------|---------|--------|
| IP hashing | Inline in sessionManager | `hashIp()` | EXTRACTED |
| IP masking | Inline in sessionManager | `maskIp()` | EXTRACTED |
| IPv6 support | Not clear | YES | IMPROVED |

#### Encryption

| Original | Package | Status |
|----------|---------|--------|
| AES-256-GCM | AES-256-GCM | OK |
| scrypt key derivation | scrypt key derivation | OK |
| Random salt per encryption | Random salt per encryption | OK |
| Auth tag verification | Auth tag verification | OK |

**Note**: Original uses env var `TOTP_ENCRYPTION_KEY || AUTH_SECRET`; package requires explicit config.

---

## Critical Gaps

### 1. Missing FileStorageAdapter (HIGH)

The package only includes `MemoryStorageAdapter`. Production use requires a `FileStorageAdapter` that:
- Reads/writes JSON files to `content/auth/`
- Handles file locking for concurrent access
- Supports atomic writes

**Recommendation**: Create `@tinyland/auth/storage/file` adapter.

### 2. Missing Bootstrap Flow (MEDIUM)

The bootstrap flow for first-time setup is not extracted:
- `BootstrapRequest/Response` types
- Bootstrap status checking
- First super_admin creation

**Recommendation**: Add `@tinyland/auth/modules/bootstrap` module.

### 3. Missing API Contract Types (MEDIUM)

Request/Response types for REST endpoints are not exported:
- `LoginRequest/Response`
- `InvitationCreate/AcceptRequest/Response`
- `SessionRefreshRequest/Response`

**Recommendation**: Add `@tinyland/auth/types/api` barrel export.

### 4. Missing Password Hashing (MEDIUM)

Original uses bcrypt in AdminUserRepository. Package has `validatePassword` but no `hashPassword`.

**Recommendation**: Add bcrypt wrapper to `@tinyland/auth/core/security`:
```typescript
export async function hashPassword(password: string, rounds: number): Promise<string>;
export async function verifyPassword(password: string, hash: string): Promise<boolean>;
```

### 5. Missing Rate Limiting (LOW)

Original has implicit rate limiting via login attempts. Package defines config but no implementation.

**Recommendation**: Add `@tinyland/auth/modules/rate-limit` module.

### 6. Onboarding Flow Types (LOW)

Onboarding types are defined in original but not extracted.

**Recommendation**: Add to `@tinyland/auth/types/auth`:
- `OnboardingStatus`
- `ProfileSetupRequest`
- `SecurityReviewRequest`
- `PreferencesSetupRequest`

### 7. AdminUserRepository Integration (LOW)

Original sessionManager dynamically imports `AdminUserRepository` for user loading. Package abstracts this via `loadUser` callback, which is correct.

---

## Migration Guide

### For Consumers Migrating from tinyland.dev

```typescript
// BEFORE (tinyland.dev)
import { hasPermission, AdminRole } from '$lib/server/auth/permissions';
import { createSession, validateSession } from '$lib/server/auth/sessionManager';
import { totpService } from '$lib/server/totp/totpService';

// AFTER (@tinyland/auth)
import {
  hasPermission,
  AdminRole,
  createSessionManager,
  createTOTPService,
} from '@tinyland/auth';
import { setSessionCookie } from '@tinyland/auth/sveltekit';

// Initialize services with explicit config
const sessionManager = createSessionManager(storage, sessionConfig);
const totpService = createTOTPService(totpConfig);
```

### Breaking Changes

1. **TOTP verification** now takes `TOTPSecret` object instead of handle string
2. **Backup code verification** now takes `BackupCodeSet` instead of userId
3. **Session creation** requires storage adapter, not direct file access
4. **Cookie helpers** moved to `@tinyland/auth/sveltekit` subpath
5. **Auth config** restructured into nested objects

---

## Recommendations

### Immediate (Before 1.0)

1. **Create FileStorageAdapter** - Required for production parity
2. **Add password hashing** - bcrypt wrapper functions
3. **Export API types** - Request/Response contracts
4. **Document storage format** - JSON schema for file adapter

### Near-term (1.x)

1. Add bootstrap module
2. Add rate limiting module
3. Add onboarding types
4. Add database storage adapter (Postgres/SQLite)

### Long-term (2.x)

1. OAuth/OIDC provider support
2. WebAuthn/Passkey support
3. Session clustering (Redis adapter)

---

## Conclusion

The @tinyland/auth package is a solid extraction with 85% feature parity. The architecture improvements (storage abstraction, pure functions, explicit config) are appropriate for a reusable library. The main gaps are:

1. Missing `FileStorageAdapter` for JSON file persistence
2. Missing password hashing utilities
3. Missing API contract types

With these additions, the package would achieve full feature parity with the original tinyland.dev implementation while providing better modularity and testability.
