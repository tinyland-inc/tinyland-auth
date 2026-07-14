








import { promises as fs } from 'fs';
import path from 'path';
import { createHash, randomBytes, randomUUID } from 'crypto';
import type { IStorageAdapter, StorageAdapterConfig, AuditEventFilters } from './interface.js';
import type {
  AdminUser,
  Session,
  SessionMetadata,
  AdminInvitation,
  BackupCodeSet,
  AuditEvent,
  EncryptedTOTPSecret,
} from '../types/index.js';
import {
  FirstUserBootstrapConflictError,
  FirstUserBootstrapValidationError,
  assertValidFirstUserBootstrapFinalization,
  cloneBootstrapValue,
  createFirstUserBootstrapReceipt,
  firstUserBootstrapMaterialDigest,
  firstUserBootstrapValueDigest,
  isExpiredInertFirstUserClaim,
  isStructurallyValidInertFirstUserClaim,
  isValidInertFirstUserClaim,
  parseFirstUserBootstrapReceipt,
  type FirstUserBootstrapFinalization,
  type FirstUserBootstrapReceipt,
  type InertFirstUserClaim,
} from './firstUserBootstrap.js';

interface ClaimedFirstUserBootstrapRecord {
  version: 1;
  status: 'claimed';
  claim: InertFirstUserClaim;
}

interface CompletedFirstUserBootstrapRecord {
  version: 1;
  status: 'completed';
  claim: InertFirstUserClaim;
  receipt: FirstUserBootstrapReceipt;
  initialState: FirstUserBootstrapFinalization;
}

type FirstUserBootstrapRecord =
  | ClaimedFirstUserBootstrapRecord
  | CompletedFirstUserBootstrapRecord;

interface FirstUserBootstrapLockOwner {
  version: 1;
  pid: number;
  token: string;
  createdAt: string;
}

const FIRST_USER_BOOTSTRAP_PROCESS_TOKEN = randomBytes(16).toString('hex');
const UNOWNED_LOCK_RECOVERY_GRACE_MS = 30_000;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function parseFirstUserBootstrapRecord(value: unknown): FirstUserBootstrapRecord {
  if (!isRecord(value) || value.version !== 1 || !isRecord(value.claim)) {
    throw new FirstUserBootstrapValidationError(
      'Corrupted first-user bootstrap record',
    );
  }
  const claimTimestamp = Date.parse(String(value.claim.claimedAt));
  if (
    !Number.isFinite(claimTimestamp) ||
    !isValidInertFirstUserClaim(value.claim, claimTimestamp)
  ) {
    throw new FirstUserBootstrapValidationError(
      'Corrupted inert first-user bootstrap claim',
    );
  }

  const claim = value.claim;
  if (value.status === 'claimed') {
    return { version: 1, status: 'claimed', claim };
  }
  if (
    value.status !== 'completed' ||
    !isRecord(value.receipt) ||
    !isRecord(value.initialState)
  ) {
    throw new FirstUserBootstrapValidationError(
      'Corrupted first-user bootstrap completion record',
    );
  }

  const initialState = value.initialState as unknown as FirstUserBootstrapFinalization;
  const finalizedAt = Date.parse(String(initialState.finalizedAt));
  assertValidFirstUserBootstrapFinalization(claim, initialState, finalizedAt);
  let receipt: FirstUserBootstrapReceipt;
  try {
    receipt = parseFirstUserBootstrapReceipt(value.receipt, {
      claim,
      finalization: initialState,
    });
  } catch (error) {
    throw new FirstUserBootstrapValidationError(
      `Corrupted immutable first-user bootstrap receipt: ${
        error instanceof Error ? error.message : String(error)
      }`,
    );
  }

  return {
    version: 1,
    status: 'completed',
    claim,
    receipt,
    initialState,
  };
}

export interface FileStorageConfig extends StorageAdapterConfig {
  
  authDir: string;
  
  totpDir: string;
  
  sessionMaxAge: number;
}

const DEFAULT_CONFIG: FileStorageConfig = {
  authDir: 'content/auth',
  totpDir: '.totp-secrets',
  sessionMaxAge: 7 * 24 * 60 * 60 * 1000, 
};
















export class FileStorageAdapter implements IStorageAdapter {
  private config: FileStorageConfig;
  private basePath: string;
  
  private locks = new Map<string, Promise<void>>();

  constructor(config: Partial<FileStorageConfig> = {}) {
    this.config = { ...DEFAULT_CONFIG, ...config };
    this.basePath = config.basePath
      ? path.resolve(config.basePath)
      : process.cwd();
  }

  
  
  

  async init(): Promise<void> {
    
    await this.ensureDir(this.getPath('admin-users.json'));
    await this.ensureDir(this.getPath('sessions.json'));
    await this.ensureDir(this.getPath('invites.json'));
    await this.ensureDir(this.getPath('logs/audit.json'));
    await this.ensureDir(path.join(this.basePath, this.config.totpDir, 'backup-codes', '.gitkeep'));
    await this.ensureDir(this.getFirstUserBootstrapPath('bootstrap-directory'));
  }

  async close(): Promise<void> {
    
  }

  async hasUsers(): Promise<boolean> {
    return (await this.getAllUsers()).length > 0;
  }

  async getAllSessions(): Promise<Session[]> {
    return this.readJsonFile<Session[]>(this.getPath('sessions.json'), []);
  }

  
  
  

  private getPath(filename: string): string {
    return path.resolve(this.basePath, this.config.authDir, filename);
  }

  private getTotpPath(handle: string): string {
    return path.resolve(this.basePath, this.config.totpDir, `${handle}.json`);
  }

  private getBackupCodesPath(userId: string): string {
    return path.resolve(this.basePath, this.config.totpDir, 'backup-codes', `${userId}.json`);
  }

  getFirstUserBootstrapPath(tenantId: string): string {
    if (typeof tenantId !== 'string' || tenantId.length === 0 || tenantId.includes('\0')) {
      throw new FirstUserBootstrapValidationError('tenantId is required');
    }
    const tenantKey = createHash('sha256').update(tenantId).digest('hex');
    return path.resolve(
      this.basePath,
      this.config.totpDir,
      'first-user-bootstrap',
      `${tenantKey}.json`,
    );
  }

  private getFirstUserBootstrapDir(): string {
    return path.resolve(this.basePath, this.config.totpDir, 'first-user-bootstrap');
  }

  private getFirstUserBootstrapLockPath(): string {
    return path.resolve(this.basePath, this.config.totpDir, '.first-user-bootstrap.lock');
  }

  private getFirstUserBootstrapLockOwnerPath(): string {
    return path.join(this.getFirstUserBootstrapLockPath(), 'owner.json');
  }

  private async ensureDir(filePath: string): Promise<void> {
    const dir = path.dirname(filePath);
    try {
      await fs.access(dir);
    } catch {
      await fs.mkdir(dir, { recursive: true });
    }
  }

  private async readJsonFile<T>(filePath: string, defaultValue: T): Promise<T> {
    try {
      await this.ensureDir(filePath);
      const content = await fs.readFile(filePath, 'utf8');
      return JSON.parse(content) as T;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
        return defaultValue;
      }
      throw error;
    }
  }

  private async readOptionalJsonFile<T>(
    filePath: string,
  ): Promise<{ exists: boolean; value: T | null }> {
    try {
      await this.ensureDir(filePath);
      const content = await fs.readFile(filePath, 'utf8');
      return { exists: true, value: JSON.parse(content) as T | null };
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
        return { exists: false, value: null };
      }
      throw error;
    }
  }

  private async removeFileIfExists(filePath: string): Promise<boolean> {
    try {
      await fs.unlink(filePath);
      return true;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') return false;
      throw error;
    }
  }

  



  private async writeJsonFile<T>(filePath: string, data: T): Promise<void> {
    await this.withFileLock(filePath, async () => {
      await this.writeJsonFileAtomic(filePath, data);
    });
  }

  



  private async writeJsonFileAtomic<T>(filePath: string, data: T): Promise<void> {
    await this.ensureDir(filePath);
    const tempPath = `${filePath}.${Date.now()}.${randomBytes(4).toString('hex')}.tmp`;

    try {
      const temp = await fs.open(tempPath, 'wx', 0o600);
      try {
        await temp.writeFile(JSON.stringify(data, null, 2), 'utf8');
        await temp.sync();
      } finally {
        await temp.close();
      }
      await fs.rename(tempPath, filePath);

      const directory = await fs.open(path.dirname(filePath), 'r');
      try {
        await directory.sync();
      } catch (error) {
        const code = (error as NodeJS.ErrnoException).code;
        if (code !== 'EINVAL' && code !== 'ENOTSUP' && code !== 'EBADF') {
          throw error;
        }
      } finally {
        await directory.close();
      }
    } catch (error) {
      
      try { await fs.unlink(tempPath); } catch {  }
      throw error;
    }
  }

  



  private async withFileLock<T>(filePath: string, operation: () => Promise<T>): Promise<T> {
    
    const existing = this.locks.get(filePath);
    if (existing) {
      await existing;
    }

    
    let resolve: () => void;
    const lockPromise = new Promise<void>(r => { resolve = r; });
    this.locks.set(filePath, lockPromise);

    try {
      return await operation();
    } finally {
      resolve!();
      this.locks.delete(filePath);
    }
  }

  private async withFirstUserBootstrapLock<T>(
    operation: () => Promise<T>,
  ): Promise<T> {
    const lockPath = this.getFirstUserBootstrapLockPath();
    await this.ensureDir(lockPath);
    const deadline = Date.now() + 5000;
    const owner: FirstUserBootstrapLockOwner = {
      version: 1,
      pid: process.pid,
      token: FIRST_USER_BOOTSTRAP_PROCESS_TOKEN,
      createdAt: new Date().toISOString(),
    };

    while (true) {
      try {
        await fs.mkdir(lockPath);
        try {
          await fs.writeFile(
            this.getFirstUserBootstrapLockOwnerPath(),
            JSON.stringify(owner),
            { encoding: 'utf8', flag: 'wx', mode: 0o600 },
          );
        } catch (error) {
          await fs.rm(lockPath, { recursive: true, force: true });
          throw error;
        }
        break;
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== 'EEXIST') throw error;
        if (await this.recoverAbandonedFirstUserBootstrapLock()) continue;
        if (Date.now() >= deadline) {
          throw new FirstUserBootstrapConflictError(
            'Timed out acquiring first-user bootstrap storage lock',
          );
        }
        await new Promise((resolve) => setTimeout(resolve, 10));
      }
    }

    try {
      return await operation();
    } finally {
      const currentOwner = await this.readFirstUserBootstrapLockOwner();
      if (currentOwner?.token !== owner.token || currentOwner.pid !== owner.pid) {
        throw new FirstUserBootstrapConflictError(
          'First-user bootstrap lock ownership changed during the operation',
        );
      }
      await fs.rm(lockPath, { recursive: true, force: false });
    }
  }

  private async readFirstUserBootstrapLockOwner(): Promise<FirstUserBootstrapLockOwner | null> {
    try {
      const value = JSON.parse(
        await fs.readFile(this.getFirstUserBootstrapLockOwnerPath(), 'utf8'),
      ) as Partial<FirstUserBootstrapLockOwner>;
      if (
        value.version !== 1 ||
        !Number.isInteger(value.pid) ||
        (value.pid as number) <= 0 ||
        typeof value.token !== 'string' ||
        value.token.length === 0 ||
        typeof value.createdAt !== 'string' ||
        !Number.isFinite(Date.parse(value.createdAt))
      ) {
        return null;
      }
      return value as FirstUserBootstrapLockOwner;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') return null;
      if (error instanceof SyntaxError) return null;
      throw error;
    }
  }

  private isProcessAlive(pid: number): boolean {
    try {
      process.kill(pid, 0);
      return true;
    } catch (error) {
      const code = (error as NodeJS.ErrnoException).code;
      if (code === 'ESRCH') return false;
      if (code === 'EPERM') return true;
      throw error;
    }
  }

  private async recoverAbandonedFirstUserBootstrapLock(): Promise<boolean> {
    const lockPath = this.getFirstUserBootstrapLockPath();
    const owner = await this.readFirstUserBootstrapLockOwner();
    if (owner && this.isProcessAlive(owner.pid)) return false;
    if (!owner) {
      let stat;
      try {
        stat = await fs.stat(lockPath);
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code === 'ENOENT') return true;
        throw error;
      }
      if (Date.now() - stat.mtimeMs < UNOWNED_LOCK_RECOVERY_GRACE_MS) {
        return false;
      }
    }

    const abandonedPath = `${lockPath}.abandoned.${process.pid}.${randomBytes(4).toString('hex')}`;
    try {
      await fs.rename(lockPath, abandonedPath);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') return true;
      return false;
    }
    await fs.rm(abandonedPath, { recursive: true, force: true });
    return true;
  }

  private async readFirstUserBootstrapRecord(
    tenantId: string,
  ): Promise<FirstUserBootstrapRecord | null> {
    const value = await this.readJsonFile<unknown | null>(
      this.getFirstUserBootstrapPath(tenantId),
      null,
    );
    return value === null ? null : parseFirstUserBootstrapRecord(value);
  }

  private async getAllFirstUserBootstrapRecords(): Promise<FirstUserBootstrapRecord[]> {
    let entries: string[];
    try {
      entries = await fs.readdir(this.getFirstUserBootstrapDir());
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') return [];
      throw error;
    }

    const records: FirstUserBootstrapRecord[] = [];
    for (const entry of entries.sort()) {
      if (!entry.endsWith('.json')) continue;
      const value = await this.readJsonFile<unknown | null>(
        path.join(this.getFirstUserBootstrapDir(), entry),
        null,
      );
      records.push(parseFirstUserBootstrapRecord(value));
    }
    return records;
  }

  private async getBootstrapRecordForActor(
    actorId?: string,
    handle?: string,
  ): Promise<FirstUserBootstrapRecord | null> {
    const records = await this.getAllFirstUserBootstrapRecords();
    return records.find((record) =>
      (actorId !== undefined && record.claim.actor.id === actorId) ||
      (handle !== undefined &&
        record.claim.actor.handle.toLowerCase() === handle.toLowerCase()),
    ) ?? null;
  }

  private async readCurrentUsers(): Promise<AdminUser[]> {
    return this.readJsonFile<AdminUser[]>(this.getPath('admin-users.json'), []);
  }

  private async getAllUsersUnlocked(): Promise<AdminUser[]> {
    const users = new Map<string, AdminUser>();
    for (const record of await this.getAllFirstUserBootstrapRecords()) {
      if (record.status === 'completed') {
        users.set(record.initialState.user.id, cloneBootstrapValue(record.initialState.user));
      }
    }
    for (const user of await this.readCurrentUsers()) {
      users.set(user.id, user);
    }
    return Array.from(users.values());
  }

  async claimFirstUserBootstrap(
    claim: InertFirstUserClaim,
  ): Promise<InertFirstUserClaim> {
    if (!isStructurallyValidInertFirstUserClaim(claim)) {
      throw new FirstUserBootstrapValidationError(
        'First-user bootstrap claim must be inert',
      );
    }

    return this.withFirstUserBootstrapLock(async () => {
      const existing = await this.readFirstUserBootstrapRecord(claim.tenantId);
      if (existing) {
        if (
          existing.status === 'claimed' &&
          firstUserBootstrapValueDigest(existing.claim) ===
            firstUserBootstrapValueDigest(claim)
        ) {
          return cloneBootstrapValue(existing.claim);
        }
        if (existing.status === 'completed') {
          throw new FirstUserBootstrapConflictError(
            'First-user bootstrap is already finalized for this tenant',
          );
        }
        if (!isExpiredInertFirstUserClaim(existing.claim)) {
          throw new FirstUserBootstrapConflictError(
            'A different first-user bootstrap claim already exists for this tenant',
          );
        }
      }
      if (!isValidInertFirstUserClaim(claim)) {
        throw new FirstUserBootstrapValidationError(
          'Replacement first-user bootstrap claim must be fresh and inert',
        );
      }
      const otherRecords = (await this.getAllFirstUserBootstrapRecords()).filter(
        (record) => record.claim.tenantId !== claim.tenantId,
      );
      if (otherRecords.length > 0) {
        throw new FirstUserBootstrapConflictError(
          'This file storage root already belongs to another bootstrap tenant',
        );
      }
      if ((await this.getAllUsersUnlocked()).length > 0) {
        throw new FirstUserBootstrapConflictError(
          'First-user bootstrap requires an empty user store',
        );
      }
      const sessions = await this.readJsonFile<Session[]>(this.getPath('sessions.json'), []);
      const totp = await this.readOptionalJsonFile<EncryptedTOTPSecret>(
        this.getTotpPath(claim.actor.handle),
      );
      const backupCodes = await this.readOptionalJsonFile<BackupCodeSet>(
        this.getBackupCodesPath(claim.actor.id),
      );
      if (
        sessions.some((session) => session.userId === claim.actor.id) ||
        (totp.exists && totp.value !== null) ||
        (backupCodes.exists && backupCodes.value !== null)
      ) {
        throw new FirstUserBootstrapConflictError(
          'Claimed actor already has session or factor state',
        );
      }

      const record: ClaimedFirstUserBootstrapRecord = {
        version: 1,
        status: 'claimed',
        claim: cloneBootstrapValue(claim),
      };
      await this.writeJsonFileAtomic(this.getFirstUserBootstrapPath(claim.tenantId), record);
      return cloneBootstrapValue(record.claim);
    });
  }

  async finalizeFirstUserBootstrap(
    finalization: FirstUserBootstrapFinalization,
  ): Promise<FirstUserBootstrapReceipt> {
    return this.withFirstUserBootstrapLock(async () => {
      const record = await this.readFirstUserBootstrapRecord(finalization.tenantId);
      if (!record) {
        throw new FirstUserBootstrapConflictError(
          'No active first-user bootstrap claim exists for this tenant',
        );
      }
      if (record.status === 'completed') {
        if (
          record.receipt.attemptId === finalization.attemptId &&
          record.receipt.materialDigest ===
            firstUserBootstrapMaterialDigest(finalization)
        ) {
          return cloneBootstrapValue(record.receipt);
        }
        throw new FirstUserBootstrapConflictError(
          'Bootstrap finalization conflicts with the immutable completion receipt',
        );
      }

      assertValidFirstUserBootstrapFinalization(record.claim, finalization);
      if ((await this.getAllUsersUnlocked()).length > 0) {
        throw new FirstUserBootstrapConflictError(
          'First-user bootstrap requires an empty user store',
        );
      }

      const initialState = cloneBootstrapValue(finalization);
      const completed: CompletedFirstUserBootstrapRecord = {
        version: 1,
        status: 'completed',
        claim: record.claim,
        receipt: createFirstUserBootstrapReceipt(record.claim, initialState),
        initialState,
      };
      await this.writeJsonFileAtomic(
        this.getFirstUserBootstrapPath(finalization.tenantId),
        completed,
      );
      return cloneBootstrapValue(completed.receipt);
    });
  }

  async getFirstUserBootstrapReceipt(
    tenantId: string,
  ): Promise<FirstUserBootstrapReceipt | null> {
    const record = await this.readFirstUserBootstrapRecord(tenantId);
    return record?.status === 'completed'
      ? cloneBootstrapValue(record.receipt)
      : null;
  }

  
  
  

  async getUser(id: string): Promise<AdminUser | null> {
    const users = await this.getAllUsers();
    return users.find(u => u.id === id) || null;
  }

  async getUserByHandle(handle: string): Promise<AdminUser | null> {
    const users = await this.getAllUsers();
    return users.find(u => u.handle === handle) || null;
  }

  async getUserByEmail(email: string): Promise<AdminUser | null> {
    const users = await this.getAllUsers();
    return users.find(u => u.email === email) || null;
  }

  async createUser(userData: Omit<AdminUser, 'id'>): Promise<AdminUser> {
    return this.withFirstUserBootstrapLock(async () => {
      const records = await this.getAllFirstUserBootstrapRecords();
      if (records.some((record) => record.status === 'claimed')) {
        throw new FirstUserBootstrapConflictError(
          'Cannot create a user while a first-user bootstrap claim is active',
        );
      }
      const users = await this.readCurrentUsers();
      const user: AdminUser = {
        id: randomUUID(),
        ...userData,
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
      };

      users.push(user);
      await this.writeJsonFileAtomic(this.getPath('admin-users.json'), users);
      return user;
    });
  }

  async updateUser(id: string, updates: Partial<AdminUser>): Promise<AdminUser> {
    return this.withFirstUserBootstrapLock(async () => {
      const allUsers = await this.getAllUsersUnlocked();
      const current = allUsers.find((user) => user.id === id);
      if (!current) {
        throw new Error(`User not found: ${id}`);
      }

      const updated: AdminUser = {
        ...current,
        ...updates,
        id,
        updatedAt: new Date().toISOString(),
      };
      const storedUsers = await this.readCurrentUsers();
      const index = storedUsers.findIndex((user) => user.id === id);
      if (index === -1) storedUsers.push(updated);
      else storedUsers[index] = updated;
      await this.writeJsonFileAtomic(this.getPath('admin-users.json'), storedUsers);
      return updated;
    });
  }

  async deleteUser(id: string): Promise<boolean> {
    return this.withFirstUserBootstrapLock(async () => {
      const bootstrapRecord = await this.getBootstrapRecordForActor(id);
      if (bootstrapRecord) {
        throw new FirstUserBootstrapConflictError(
          bootstrapRecord.status === 'completed'
            ? 'Cannot delete a bootstrap-finalized actor'
            : 'Cannot delete a claimed first-user actor',
        );
      }

      const users = await this.readCurrentUsers();
      const index = users.findIndex((user) => user.id === id);
      if (index === -1) return false;
      const user = users[index];
      const sessions = await this.readJsonFile<Session[]>(this.getPath('sessions.json'), []);

      users[index] = {
        ...user,
        isActive: false,
        updatedAt: new Date().toISOString(),
      };
      await this.writeJsonFileAtomic(this.getPath('admin-users.json'), users);
      await this.writeJsonFileAtomic(
        this.getPath('sessions.json'),
        sessions.filter((session) => session.userId !== id),
      );
      await this.removeFileIfExists(this.getTotpPath(user.handle));
      await this.removeFileIfExists(this.getBackupCodesPath(id));
      users.splice(index, 1);
      await this.writeJsonFileAtomic(this.getPath('admin-users.json'), users);
      return true;
    });
  }

  async getAllUsers(): Promise<AdminUser[]> {
    return this.getAllUsersUnlocked();
  }

  
  
  

  async getSession(id: string): Promise<Session | null> {
    const sessions = await this.readJsonFile<Session[]>(this.getPath('sessions.json'), []);
    return sessions.find(s => s.id === id) || null;
  }

  async createSession(
    userId: string,
    userData: Partial<AdminUser>,
    metadata?: SessionMetadata
  ): Promise<Session> {
    return this.withFirstUserBootstrapLock(async () => {
      if (userData.id !== undefined && userData.id !== userId) {
        throw new FirstUserBootstrapConflictError(
          'Session user identity does not match userId',
        );
      }
      const bootstrapRecord = await this.getBootstrapRecordForActor(userId);
      if (bootstrapRecord?.status === 'claimed') {
        throw new FirstUserBootstrapConflictError(
          'Claimed first-user actor has no session authority before finalization',
        );
      }
      const sessions = await this.readJsonFile<Session[]>(this.getPath('sessions.json'), []);
      const now = new Date();
      const expires = new Date(now.getTime() + this.config.sessionMaxAge);

      const session: Session = {
        id: randomBytes(32).toString('hex'),
        userId,
        expires: expires.toISOString(),
        expiresAt: expires.toISOString(),
        createdAt: now.toISOString(),
        user: userData.id ? {
          id: userData.id,
          username: userData.handle || '',
          name: userData.displayName || userData.handle || '',
          role: userData.role || 'viewer',
          needsOnboarding: userData.needsOnboarding,
          onboardingStep: userData.onboardingStep,
        } : undefined,
        clientIp: metadata?.clientIp || '',
        clientIpMasked: metadata?.clientIpMasked,
        userAgent: metadata?.userAgent || '',
        deviceType: metadata?.deviceType,
        browserFingerprint: metadata?.browserFingerprint,
        geoLocation: metadata?.geoLocation,
      };

      sessions.push(session);
      await this.writeJsonFileAtomic(this.getPath('sessions.json'), sessions);
      return session;
    });
  }

  async updateSession(id: string, updates: Partial<Session>): Promise<Session> {
    return this.withFirstUserBootstrapLock(async () => {
      const sessions = await this.readJsonFile<Session[]>(this.getPath('sessions.json'), []);
      const index = sessions.findIndex(s => s.id === id);

      if (index === -1) {
        throw new Error(`Session not found: ${id}`);
      }
      const current = sessions[index];
      if (updates.userId !== undefined && updates.userId !== current.userId) {
        throw new FirstUserBootstrapConflictError(
          'Session user identity is immutable',
        );
      }
      const currentNestedUserId = current.user?.id ?? current.userId;
      if (
        updates.user?.id !== undefined &&
        updates.user.id !== currentNestedUserId
      ) {
        throw new FirstUserBootstrapConflictError(
          'Nested session user identity is immutable',
        );
      }

      const updated = {
        ...current,
        ...cloneBootstrapValue(updates),
        id: current.id,
        userId: current.userId,
      };
      sessions[index] = updated;
      await this.writeJsonFileAtomic(this.getPath('sessions.json'), sessions);
      return cloneBootstrapValue(updated);
    });
  }

  async deleteSession(id: string): Promise<boolean> {
    const sessions = await this.readJsonFile<Session[]>(this.getPath('sessions.json'), []);
    const index = sessions.findIndex(s => s.id === id);

    if (index === -1) return false;

    sessions.splice(index, 1);
    await this.writeJsonFile(this.getPath('sessions.json'), sessions);
    return true;
  }

  async deleteUserSessions(userId: string): Promise<number> {
    const sessions = await this.readJsonFile<Session[]>(this.getPath('sessions.json'), []);
    const before = sessions.length;
    const filtered = sessions.filter(s => s.userId !== userId);
    await this.writeJsonFile(this.getPath('sessions.json'), filtered);
    return before - filtered.length;
  }

  async getSessionsByUser(userId: string): Promise<Session[]> {
    const sessions = await this.readJsonFile<Session[]>(this.getPath('sessions.json'), []);
    return sessions.filter(s => s.userId === userId);
  }

  async cleanupExpiredSessions(): Promise<number> {
    const sessions = await this.readJsonFile<Session[]>(this.getPath('sessions.json'), []);
    const now = new Date();
    const before = sessions.length;
    const filtered = sessions.filter(s => new Date(s.expires) > now);
    await this.writeJsonFile(this.getPath('sessions.json'), filtered);
    return before - filtered.length;
  }

  
  
  

  async getTOTPSecret(handle: string): Promise<EncryptedTOTPSecret | null> {
    const current = await this.readOptionalJsonFile<EncryptedTOTPSecret>(
      this.getTotpPath(handle),
    );
    if (current.exists) return current.value;
    for (const record of await this.getAllFirstUserBootstrapRecords()) {
      if (
        record.status === 'completed' &&
        record.initialState.totpSecret.handle.toLowerCase() === handle.toLowerCase()
      ) {
        return cloneBootstrapValue(record.initialState.totpSecret);
      }
    }
    return null;
  }

  async saveTOTPSecret(handle: string, secret: EncryptedTOTPSecret): Promise<void> {
    await this.withFirstUserBootstrapLock(async () => {
      const record = await this.getBootstrapRecordForActor(secret.userId, handle);
      if (record?.status === 'claimed') {
        throw new FirstUserBootstrapConflictError(
          'Cannot enroll TOTP for a claimed actor before finalization',
        );
      }
      await this.writeJsonFileAtomic(this.getTotpPath(handle), secret);
    });
  }

  async deleteTOTPSecret(handle: string): Promise<boolean> {
    return this.withFirstUserBootstrapLock(async () => {
      const bootstrapRecord = await this.getBootstrapRecordForActor(undefined, handle);
      if (bootstrapRecord) {
        throw new FirstUserBootstrapConflictError(
          'Cannot delete a claimed or bootstrap-finalized TOTP factor',
        );
      }
      return this.removeFileIfExists(this.getTotpPath(handle));
    });
  }

  
  
  

  async getBackupCodes(userId: string): Promise<BackupCodeSet | null> {
    const current = await this.readOptionalJsonFile<BackupCodeSet>(
      this.getBackupCodesPath(userId),
    );
    if (current.exists) return current.value;
    for (const record of await this.getAllFirstUserBootstrapRecords()) {
      if (
        record.status === 'completed' &&
        record.initialState.backupCodes.userId === userId
      ) {
        return cloneBootstrapValue(record.initialState.backupCodes);
      }
    }
    return null;
  }

  async saveBackupCodes(userId: string, codeSet: BackupCodeSet): Promise<void> {
    await this.withFirstUserBootstrapLock(async () => {
      const record = await this.getBootstrapRecordForActor(userId);
      if (record?.status === 'claimed') {
        throw new FirstUserBootstrapConflictError(
          'Cannot save backup codes for a claimed actor before finalization',
        );
      }
      await this.writeJsonFileAtomic(this.getBackupCodesPath(userId), codeSet);
    });
  }

  async deleteBackupCodes(userId: string): Promise<boolean> {
    return this.withFirstUserBootstrapLock(async () => {
      const bootstrapRecord = await this.getBootstrapRecordForActor(userId);
      if (bootstrapRecord) {
        throw new FirstUserBootstrapConflictError(
          'Cannot delete claimed or bootstrap-finalized backup codes',
        );
      }
      return this.removeFileIfExists(this.getBackupCodesPath(userId));
    });
  }

  
  
  

  async getInvitation(token: string): Promise<AdminInvitation | null> {
    const invites = await this.readJsonFile<AdminInvitation[]>(this.getPath('invites.json'), []);
    return invites.find(i => i.token === token) || null;
  }

  async getInvitationById(id: string): Promise<AdminInvitation | null> {
    const invites = await this.readJsonFile<AdminInvitation[]>(this.getPath('invites.json'), []);
    return invites.find(i => i.id === id) || null;
  }

  async createInvitation(data: Omit<AdminInvitation, 'id'>): Promise<AdminInvitation> {
    const invites = await this.readJsonFile<AdminInvitation[]>(this.getPath('invites.json'), []);

    const invitation: AdminInvitation = {
      id: randomUUID(),
      ...data,
    };

    invites.push(invitation);
    await this.writeJsonFile(this.getPath('invites.json'), invites);
    return invitation;
  }

  async updateInvitation(token: string, updates: Partial<AdminInvitation>): Promise<AdminInvitation> {
    const invites = await this.readJsonFile<AdminInvitation[]>(this.getPath('invites.json'), []);
    const index = invites.findIndex(i => i.token === token);

    if (index === -1) {
      throw new Error(`Invitation not found: ${token}`);
    }

    invites[index] = { ...invites[index], ...updates };
    await this.writeJsonFile(this.getPath('invites.json'), invites);
    return invites[index];
  }

  async deleteInvitation(token: string): Promise<boolean> {
    const invites = await this.readJsonFile<AdminInvitation[]>(this.getPath('invites.json'), []);
    const index = invites.findIndex(i => i.token === token);

    if (index === -1) return false;

    invites.splice(index, 1);
    await this.writeJsonFile(this.getPath('invites.json'), invites);
    return true;
  }

  async getPendingInvitations(): Promise<AdminInvitation[]> {
    const invites = await this.readJsonFile<AdminInvitation[]>(this.getPath('invites.json'), []);
    const now = new Date();
    return invites.filter(i => new Date(i.expiresAt) > now && !i.usedAt && i.isActive);
  }

  async getAllInvitations(): Promise<AdminInvitation[]> {
    return this.readJsonFile<AdminInvitation[]>(this.getPath('invites.json'), []);
  }

  async cleanupExpiredInvitations(): Promise<number> {
    const invites = await this.readJsonFile<AdminInvitation[]>(this.getPath('invites.json'), []);
    const now = new Date();
    const before = invites.length;
    const filtered = invites.filter(i =>
      new Date(i.expiresAt) > now || i.usedAt
    );
    await this.writeJsonFile(this.getPath('invites.json'), filtered);
    return before - filtered.length;
  }

  
  
  

  async logAuditEvent(event: Omit<AuditEvent, 'id'>): Promise<AuditEvent> {
    const logPath = this.getPath('logs/audit.json');
    const events = await this.readJsonFile<AuditEvent[]>(logPath, []);

    const auditEvent: AuditEvent = {
      id: randomUUID(),
      ...event,
    };

    events.push(auditEvent);

    
    if (events.length > 10000) {
      events.splice(0, events.length - 10000);
    }

    await this.writeJsonFile(logPath, events);
    return auditEvent;
  }

  async getAuditEvents(filters: AuditEventFilters): Promise<AuditEvent[]> {
    const logPath = this.getPath('logs/audit.json');
    let events = await this.readJsonFile<AuditEvent[]>(logPath, []);

    if (filters.type) {
      events = events.filter(e => e.type === filters.type);
    }

    if (filters.userId) {
      events = events.filter(e => e.userId === filters.userId || e.targetUserId === filters.userId);
    }

    if (filters.severity) {
      events = events.filter(e => e.severity === filters.severity);
    }

    if (filters.startDate) {
      const start = filters.startDate.getTime();
      events = events.filter(e => new Date(e.timestamp).getTime() >= start);
    }

    if (filters.endDate) {
      const end = filters.endDate.getTime();
      events = events.filter(e => new Date(e.timestamp).getTime() <= end);
    }

    const limit = filters.limit || 100;
    const offset = filters.offset || 0;

    return events.slice(offset, offset + limit);
  }

  async getRecentAuditEvents(limit: number = 100): Promise<AuditEvent[]> {
    const logPath = this.getPath('logs/audit.json');
    const events = await this.readJsonFile<AuditEvent[]>(logPath, []);
    return events.slice(-limit).reverse();
  }
}




export function createFileStorageAdapter(config?: Partial<FileStorageConfig>): FileStorageAdapter {
  return new FileStorageAdapter(config);
}
