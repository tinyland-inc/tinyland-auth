/**
 * Fixed-tenant storage adapter wrapper.
 *
 * Bridges between tenant-scoped storage backends (Pattern B — every method
 * takes `tenantId` as its first parameter) and the standard `IStorageAdapter`
 * (Pattern A — no tenantId parameter). Useful for single-tenant deployments
 * built on top of a multi-tenant backend like @tummycrypt/tinyland-auth-pg.
 *
 * @example
 * ```typescript
 * import {
 *   createFixedTenantStorageAdapter,
 *   resolveAuthTenantId,
 * } from "@tummycrypt/tinyland-auth/storage";
 * import { createNodePgStorageAdapter } from "@tummycrypt/tinyland-auth-pg";
 *
 * const tenantId = resolveAuthTenantId({
 *   ELDERS_AUTH_TENANT_ID: process.env.ELDERS_AUTH_TENANT_ID,
 *   AUTH_TENANT_ID: process.env.AUTH_TENANT_ID,
 * });
 * const tenantScoped = createNodePgStorageAdapter({ connectionString });
 * const adapter = createFixedTenantStorageAdapter(tenantId, tenantScoped);
 * await adapter.init();
 * ```
 */

import type {
  AdminInvitation,
  AdminUser,
  AuditEvent,
  BackupCodeSet,
  EncryptedTOTPSecret,
  Session,
  SessionMetadata,
} from "../types/index.js";
import type { AuditEventFilters, IStorageAdapter } from "./interface.js";

const UUID_RE =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

/**
 * Pattern B (multi-tenant) storage interface.
 *
 * Every method takes `tenantId` as its first parameter. Backends like
 * `@tummycrypt/tinyland-auth-pg` already implement this shape, so they
 * structurally satisfy this interface without explicit declaration.
 */
export interface TenantScopedStorage {
  init(): Promise<void>;
  close(): Promise<void>;

  getUser(tenantId: string, id: string): Promise<AdminUser | null>;
  getUserByHandle(tenantId: string, handle: string): Promise<AdminUser | null>;
  getUserByEmail(tenantId: string, email: string): Promise<AdminUser | null>;
  getAllUsers(tenantId: string): Promise<AdminUser[]>;
  createUser(
    tenantId: string,
    user: Omit<AdminUser, "id" | "tenantId">,
  ): Promise<AdminUser>;
  updateUser(
    tenantId: string,
    id: string,
    updates: Partial<AdminUser>,
  ): Promise<AdminUser>;
  deleteUser(tenantId: string, id: string): Promise<boolean>;
  hasUsers(tenantId: string): Promise<boolean>;

  getSession(tenantId: string, id: string): Promise<Session | null>;
  getSessionsByUser(tenantId: string, userId: string): Promise<Session[]>;
  getAllSessions(tenantId: string): Promise<Session[]>;
  createSession(
    tenantId: string,
    userId: string,
    user: Partial<AdminUser>,
    metadata?: SessionMetadata,
  ): Promise<Session>;
  updateSession(
    tenantId: string,
    id: string,
    updates: Partial<Session>,
  ): Promise<Session>;
  deleteSession(tenantId: string, id: string): Promise<boolean>;
  deleteUserSessions(tenantId: string, userId: string): Promise<number>;
  cleanupExpiredSessions(tenantId: string): Promise<number>;

  getTOTPSecret(
    tenantId: string,
    handle: string,
  ): Promise<EncryptedTOTPSecret | null>;
  saveTOTPSecret(
    tenantId: string,
    handle: string,
    secret: EncryptedTOTPSecret,
  ): Promise<void>;
  deleteTOTPSecret(tenantId: string, handle: string): Promise<boolean>;

  getBackupCodes(
    tenantId: string,
    userId: string,
  ): Promise<BackupCodeSet | null>;
  saveBackupCodes(
    tenantId: string,
    userId: string,
    codes: BackupCodeSet,
  ): Promise<void>;
  deleteBackupCodes(tenantId: string, userId: string): Promise<boolean>;

  getInvitation(
    tenantId: string,
    token: string,
  ): Promise<AdminInvitation | null>;
  getInvitationById(
    tenantId: string,
    id: string,
  ): Promise<AdminInvitation | null>;
  getAllInvitations(tenantId: string): Promise<AdminInvitation[]>;
  getPendingInvitations(tenantId: string): Promise<AdminInvitation[]>;
  createInvitation(
    tenantId: string,
    invitation: Omit<AdminInvitation, "id">,
  ): Promise<AdminInvitation>;
  updateInvitation(
    tenantId: string,
    token: string,
    updates: Partial<AdminInvitation>,
  ): Promise<AdminInvitation>;
  deleteInvitation(tenantId: string, token: string): Promise<boolean>;
  cleanupExpiredInvitations(tenantId: string): Promise<number>;

  logAuditEvent(
    tenantId: string,
    event: Omit<AuditEvent, "id">,
  ): Promise<AuditEvent>;
  getAuditEvents(
    tenantId: string,
    filters: AuditEventFilters,
  ): Promise<AuditEvent[]>;
  getRecentAuditEvents(
    tenantId: string,
    limit?: number,
  ): Promise<AuditEvent[]>;
}

/**
 * Resolve a tenant id from a set of candidate environment values.
 *
 * Returns the first non-empty value that parses as a UUID, lowercased.
 * Throws if no candidate is set, or if the chosen value is not a UUID.
 */
export function resolveAuthTenantId(
  values: Record<string, string | undefined>,
): string {
  const tenantId = Object.values(values).find(
    (v): v is string => typeof v === "string" && v.length > 0,
  );

  if (!tenantId) {
    const keys = Object.keys(values).join(" or ");
    throw new Error(
      `${keys || "tenant id"} is required for the tenant-scoped auth storage.`,
    );
  }

  if (!UUID_RE.test(tenantId)) {
    throw new Error(
      `tenant id must be a UUID, received: ${tenantId}`,
    );
  }

  return tenantId.toLowerCase();
}

/**
 * Adapter that wraps a `TenantScopedStorage` and exposes it as `IStorageAdapter`
 * by injecting a fixed tenantId on every operation.
 */
class FixedTenantStorageAdapter implements IStorageAdapter {
  constructor(
    private readonly tenantId: string,
    private readonly storage: TenantScopedStorage,
  ) {}

  init() {
    return this.storage.init();
  }
  close() {
    return this.storage.close();
  }

  getUser(id: string) {
    return this.storage.getUser(this.tenantId, id);
  }
  getUserByHandle(handle: string) {
    return this.storage.getUserByHandle(this.tenantId, handle);
  }
  getUserByEmail(email: string) {
    return this.storage.getUserByEmail(this.tenantId, email);
  }
  getAllUsers() {
    return this.storage.getAllUsers(this.tenantId);
  }
  createUser(user: Omit<AdminUser, "id">) {
    return this.storage.createUser(
      this.tenantId,
      user as Omit<AdminUser, "id" | "tenantId">,
    );
  }
  updateUser(id: string, updates: Partial<AdminUser>) {
    return this.storage.updateUser(this.tenantId, id, updates);
  }
  deleteUser(id: string) {
    return this.storage.deleteUser(this.tenantId, id);
  }
  hasUsers() {
    return this.storage.hasUsers(this.tenantId);
  }

  getSession(id: string) {
    return this.storage.getSession(this.tenantId, id);
  }
  getSessionsByUser(userId: string) {
    return this.storage.getSessionsByUser(this.tenantId, userId);
  }
  getAllSessions() {
    return this.storage.getAllSessions(this.tenantId);
  }
  createSession(
    userId: string,
    user: Partial<AdminUser>,
    metadata?: SessionMetadata,
  ) {
    return this.storage.createSession(this.tenantId, userId, user, metadata);
  }
  updateSession(id: string, updates: Partial<Session>) {
    return this.storage.updateSession(this.tenantId, id, updates);
  }
  deleteSession(id: string) {
    return this.storage.deleteSession(this.tenantId, id);
  }
  deleteUserSessions(userId: string) {
    return this.storage.deleteUserSessions(this.tenantId, userId);
  }
  cleanupExpiredSessions() {
    return this.storage.cleanupExpiredSessions(this.tenantId);
  }

  getTOTPSecret(handle: string) {
    return this.storage.getTOTPSecret(this.tenantId, handle);
  }
  saveTOTPSecret(handle: string, secret: EncryptedTOTPSecret) {
    return this.storage.saveTOTPSecret(this.tenantId, handle, secret);
  }
  deleteTOTPSecret(handle: string) {
    return this.storage.deleteTOTPSecret(this.tenantId, handle);
  }

  getBackupCodes(userId: string) {
    return this.storage.getBackupCodes(this.tenantId, userId);
  }
  saveBackupCodes(userId: string, codes: BackupCodeSet) {
    return this.storage.saveBackupCodes(this.tenantId, userId, codes);
  }
  deleteBackupCodes(userId: string) {
    return this.storage.deleteBackupCodes(this.tenantId, userId);
  }

  getInvitation(token: string) {
    return this.storage.getInvitation(this.tenantId, token);
  }
  getInvitationById(id: string) {
    return this.storage.getInvitationById(this.tenantId, id);
  }
  getAllInvitations() {
    return this.storage.getAllInvitations(this.tenantId);
  }
  getPendingInvitations() {
    return this.storage.getPendingInvitations(this.tenantId);
  }
  createInvitation(invitation: Omit<AdminInvitation, "id">) {
    return this.storage.createInvitation(this.tenantId, invitation);
  }
  updateInvitation(token: string, updates: Partial<AdminInvitation>) {
    return this.storage.updateInvitation(this.tenantId, token, updates);
  }
  deleteInvitation(token: string) {
    return this.storage.deleteInvitation(this.tenantId, token);
  }
  cleanupExpiredInvitations() {
    return this.storage.cleanupExpiredInvitations(this.tenantId);
  }

  logAuditEvent(event: Omit<AuditEvent, "id">) {
    return this.storage.logAuditEvent(this.tenantId, event);
  }
  getAuditEvents(filters: AuditEventFilters) {
    return this.storage.getAuditEvents(this.tenantId, filters);
  }
  getRecentAuditEvents(limit?: number) {
    return this.storage.getRecentAuditEvents(this.tenantId, limit);
  }
}

/**
 * Wrap a tenant-scoped storage backend in a fixed-tenant adapter that
 * exposes the standard `IStorageAdapter` shape.
 *
 * The returned adapter is a thin, stateless wrapper — every call delegates
 * to the underlying storage with `tenantId` injected as the first argument.
 */
export function createFixedTenantStorageAdapter(
  tenantId: string,
  storage: TenantScopedStorage,
): IStorageAdapter {
  if (!UUID_RE.test(tenantId)) {
    throw new Error(`tenantId must be a UUID, received: ${tenantId}`);
  }
  return new FixedTenantStorageAdapter(tenantId.toLowerCase(), storage);
}
