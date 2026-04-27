import { describe, expect, it, vi } from "vitest";
import {
  createFixedTenantStorageAdapter,
  resolveAuthTenantId,
  type TenantScopedStorage,
} from "../src/storage/fixedTenant.js";
import type { AdminUser } from "../src/types/index.js";

const TENANT = "12345678-1234-4123-8123-123456789abc";

function makeStub(): TenantScopedStorage {
  return {
    init: vi.fn().mockResolvedValue(undefined),
    close: vi.fn().mockResolvedValue(undefined),
    getUser: vi.fn().mockResolvedValue(null),
    getUserByHandle: vi.fn().mockResolvedValue(null),
    getUserByEmail: vi.fn().mockResolvedValue(null),
    getAllUsers: vi.fn().mockResolvedValue([]),
    createUser: vi.fn().mockImplementation(async (_t, u) => ({
      id: "u1",
      tenantId: _t,
      ...u,
    } as AdminUser)),
    updateUser: vi.fn().mockResolvedValue({} as AdminUser),
    deleteUser: vi.fn().mockResolvedValue(true),
    hasUsers: vi.fn().mockResolvedValue(false),
    getSession: vi.fn().mockResolvedValue(null),
    getSessionsByUser: vi.fn().mockResolvedValue([]),
    getAllSessions: vi.fn().mockResolvedValue([]),
    createSession: vi.fn().mockResolvedValue({} as never),
    updateSession: vi.fn().mockResolvedValue({} as never),
    deleteSession: vi.fn().mockResolvedValue(true),
    deleteUserSessions: vi.fn().mockResolvedValue(0),
    cleanupExpiredSessions: vi.fn().mockResolvedValue(0),
    getTOTPSecret: vi.fn().mockResolvedValue(null),
    saveTOTPSecret: vi.fn().mockResolvedValue(undefined),
    deleteTOTPSecret: vi.fn().mockResolvedValue(true),
    getBackupCodes: vi.fn().mockResolvedValue(null),
    saveBackupCodes: vi.fn().mockResolvedValue(undefined),
    deleteBackupCodes: vi.fn().mockResolvedValue(true),
    getInvitation: vi.fn().mockResolvedValue(null),
    getInvitationById: vi.fn().mockResolvedValue(null),
    getAllInvitations: vi.fn().mockResolvedValue([]),
    getPendingInvitations: vi.fn().mockResolvedValue([]),
    createInvitation: vi.fn().mockResolvedValue({} as never),
    updateInvitation: vi.fn().mockResolvedValue({} as never),
    deleteInvitation: vi.fn().mockResolvedValue(true),
    cleanupExpiredInvitations: vi.fn().mockResolvedValue(0),
    logAuditEvent: vi.fn().mockResolvedValue({} as never),
    getAuditEvents: vi.fn().mockResolvedValue([]),
    getRecentAuditEvents: vi.fn().mockResolvedValue([]),
  };
}

describe("resolveAuthTenantId", () => {
  it("returns the tenant from the first non-empty value", () => {
    const result = resolveAuthTenantId({
      ELDERS_AUTH_TENANT_ID: TENANT,
      AUTH_TENANT_ID: undefined,
    });
    expect(result).toBe(TENANT);
  });

  it("falls back to subsequent keys when earlier ones are empty", () => {
    const result = resolveAuthTenantId({
      FIRST: undefined,
      SECOND: TENANT,
    });
    expect(result).toBe(TENANT);
  });

  it("lowercases the tenant id", () => {
    const upper = TENANT.toUpperCase();
    expect(resolveAuthTenantId({ A: upper })).toBe(TENANT);
  });

  it("throws when no value is set", () => {
    expect(() =>
      resolveAuthTenantId({ A: undefined, B: undefined }),
    ).toThrowError(/required/);
  });

  it("throws when the tenant id is not a UUID", () => {
    expect(() => resolveAuthTenantId({ A: "not-a-uuid" })).toThrowError(/UUID/);
  });
});

describe("createFixedTenantStorageAdapter", () => {
  it("rejects non-UUID tenant ids", () => {
    expect(() =>
      createFixedTenantStorageAdapter("not-a-uuid", makeStub()),
    ).toThrowError(/UUID/);
  });

  it("normalizes uppercase tenant ids to lowercase", async () => {
    const stub = makeStub();
    const adapter = createFixedTenantStorageAdapter(
      TENANT.toUpperCase(),
      stub,
    );
    await adapter.getUser("u1");
    expect(stub.getUser).toHaveBeenCalledWith(TENANT, "u1");
  });

  it("forwards getUser with the fixed tenant id", async () => {
    const stub = makeStub();
    const adapter = createFixedTenantStorageAdapter(TENANT, stub);
    await adapter.getUser("u1");
    expect(stub.getUser).toHaveBeenCalledWith(TENANT, "u1");
  });

  it("forwards getUserByHandle", async () => {
    const stub = makeStub();
    const adapter = createFixedTenantStorageAdapter(TENANT, stub);
    await adapter.getUserByHandle("alice");
    expect(stub.getUserByHandle).toHaveBeenCalledWith(TENANT, "alice");
  });

  it("forwards createUser without leaking IStorageAdapter shape", async () => {
    const stub = makeStub();
    const adapter = createFixedTenantStorageAdapter(TENANT, stub);
    const user = {
      handle: "alice",
      email: "alice@example.com",
      passwordHash: "x",
      role: "admin",
      isActive: true,
      needsOnboarding: false,
      onboardingStep: 0,
    } as unknown as Omit<AdminUser, "id">;
    await adapter.createUser(user);
    expect(stub.createUser).toHaveBeenCalledWith(TENANT, user);
  });

  it("forwards createSession with metadata", async () => {
    const stub = makeStub();
    const adapter = createFixedTenantStorageAdapter(TENANT, stub);
    const meta = { ipAddress: "127.0.0.1", userAgent: "test" } as never;
    await adapter.createSession("u1", { id: "u1" } as Partial<AdminUser>, meta);
    expect(stub.createSession).toHaveBeenCalledWith(
      TENANT,
      "u1",
      { id: "u1" },
      meta,
    );
  });

  it("forwards init/close to underlying storage", async () => {
    const stub = makeStub();
    const adapter = createFixedTenantStorageAdapter(TENANT, stub);
    await adapter.init();
    await adapter.close();
    expect(stub.init).toHaveBeenCalled();
    expect(stub.close).toHaveBeenCalled();
  });

  it("forwards audit operations with tenant id", async () => {
    const stub = makeStub();
    const adapter = createFixedTenantStorageAdapter(TENANT, stub);
    await adapter.getRecentAuditEvents(50);
    expect(stub.getRecentAuditEvents).toHaveBeenCalledWith(TENANT, 50);
  });

  it("forwards TOTP and backup code operations", async () => {
    const stub = makeStub();
    const adapter = createFixedTenantStorageAdapter(TENANT, stub);
    await adapter.getTOTPSecret("alice");
    await adapter.deleteBackupCodes("u1");
    expect(stub.getTOTPSecret).toHaveBeenCalledWith(TENANT, "alice");
    expect(stub.deleteBackupCodes).toHaveBeenCalledWith(TENANT, "u1");
  });
});
