/**
 * File Storage Adapter
 *
 * Backward-compatible file-based storage for tinyland.dev.
 * Reads/writes JSON files to content/auth/ directory.
 *
 * @module @tinyland/auth/storage/file
 */
import type { IStorageAdapter, StorageAdapterConfig, AuditEventFilters } from './interface.js';
import type { AdminUser, Session, SessionMetadata, AdminInvitation, BackupCodeSet, AuditEvent, EncryptedTOTPSecret } from '../types/index.js';
export interface FileStorageConfig extends StorageAdapterConfig {
    /** Base directory for auth data (default: content/auth) */
    authDir: string;
    /** Directory for TOTP secrets (default: .totp-secrets) */
    totpDir: string;
    /** Session max age in milliseconds */
    sessionMaxAge: number;
}
/**
 * File-based storage adapter
 *
 * Compatible with existing tinyland.dev file structure:
 * - content/auth/admin-users.json
 * - content/auth/sessions.json
 * - content/auth/invites.json
 * - content/auth/logs/audit.json
 * - .totp-secrets/{handle}.json
 * - .totp-secrets/backup-codes/{userId}.json
 */
export declare class FileStorageAdapter implements IStorageAdapter {
    private config;
    private basePath;
    constructor(config?: Partial<FileStorageConfig>);
    init(): Promise<void>;
    close(): Promise<void>;
    hasUsers(): Promise<boolean>;
    getAllSessions(): Promise<Session[]>;
    private getPath;
    private getTotpPath;
    private getBackupCodesPath;
    private ensureDir;
    private readJsonFile;
    private writeJsonFile;
    getUser(id: string): Promise<AdminUser | null>;
    getUserByHandle(handle: string): Promise<AdminUser | null>;
    getUserByEmail(email: string): Promise<AdminUser | null>;
    createUser(userData: Omit<AdminUser, 'id'>): Promise<AdminUser>;
    updateUser(id: string, updates: Partial<AdminUser>): Promise<AdminUser>;
    deleteUser(id: string): Promise<boolean>;
    getAllUsers(): Promise<AdminUser[]>;
    getSession(id: string): Promise<Session | null>;
    createSession(userId: string, userData: Partial<AdminUser>, metadata?: SessionMetadata): Promise<Session>;
    updateSession(id: string, updates: Partial<Session>): Promise<Session>;
    deleteSession(id: string): Promise<boolean>;
    deleteUserSessions(userId: string): Promise<number>;
    getSessionsByUser(userId: string): Promise<Session[]>;
    cleanupExpiredSessions(): Promise<number>;
    getTOTPSecret(handle: string): Promise<EncryptedTOTPSecret | null>;
    saveTOTPSecret(handle: string, secret: EncryptedTOTPSecret): Promise<void>;
    deleteTOTPSecret(handle: string): Promise<boolean>;
    getBackupCodes(userId: string): Promise<BackupCodeSet | null>;
    saveBackupCodes(userId: string, codeSet: BackupCodeSet): Promise<void>;
    deleteBackupCodes(userId: string): Promise<boolean>;
    getInvitation(token: string): Promise<AdminInvitation | null>;
    getInvitationById(id: string): Promise<AdminInvitation | null>;
    createInvitation(data: Omit<AdminInvitation, 'id'>): Promise<AdminInvitation>;
    updateInvitation(token: string, updates: Partial<AdminInvitation>): Promise<AdminInvitation>;
    deleteInvitation(token: string): Promise<boolean>;
    getPendingInvitations(): Promise<AdminInvitation[]>;
    getAllInvitations(): Promise<AdminInvitation[]>;
    cleanupExpiredInvitations(): Promise<number>;
    logAuditEvent(event: Omit<AuditEvent, 'id'>): Promise<AuditEvent>;
    getAuditEvents(filters: AuditEventFilters): Promise<AuditEvent[]>;
    getRecentAuditEvents(limit?: number): Promise<AuditEvent[]>;
}
/**
 * Create a file storage adapter instance
 */
export declare function createFileStorageAdapter(config?: Partial<FileStorageConfig>): FileStorageAdapter;
//# sourceMappingURL=file.d.ts.map