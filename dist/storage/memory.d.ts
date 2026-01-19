/**
 * In-Memory Storage Adapter
 *
 * A simple in-memory storage implementation for testing and development.
 * Data is lost when the process ends.
 *
 * @module @tinyland/auth/storage/memory
 */
import type { IStorageAdapter, AuditEventFilters } from './interface.js';
import type { AdminUser, Session, SessionMetadata, EncryptedTOTPSecret, BackupCodeSet, AdminInvitation, AuditEvent } from '../types/auth.js';
export declare class MemoryStorageAdapter implements IStorageAdapter {
    private users;
    private usersByHandle;
    private usersByEmail;
    private sessions;
    private totpSecrets;
    private backupCodes;
    private invitations;
    private auditEvents;
    init(): Promise<void>;
    close(): Promise<void>;
    getUser(id: string): Promise<AdminUser | null>;
    getUserByHandle(handle: string): Promise<AdminUser | null>;
    getUserByEmail(email: string): Promise<AdminUser | null>;
    getAllUsers(): Promise<AdminUser[]>;
    createUser(user: Omit<AdminUser, 'id'>): Promise<AdminUser>;
    updateUser(id: string, updates: Partial<AdminUser>): Promise<AdminUser>;
    deleteUser(id: string): Promise<boolean>;
    hasUsers(): Promise<boolean>;
    getSession(id: string): Promise<Session | null>;
    getSessionsByUser(userId: string): Promise<Session[]>;
    getAllSessions(): Promise<Session[]>;
    createSession(userId: string, user: Partial<AdminUser>, metadata?: SessionMetadata): Promise<Session>;
    updateSession(id: string, updates: Partial<Session>): Promise<Session>;
    deleteSession(id: string): Promise<boolean>;
    deleteUserSessions(userId: string): Promise<number>;
    cleanupExpiredSessions(): Promise<number>;
    getTOTPSecret(handle: string): Promise<EncryptedTOTPSecret | null>;
    saveTOTPSecret(handle: string, secret: EncryptedTOTPSecret): Promise<void>;
    deleteTOTPSecret(handle: string): Promise<boolean>;
    getBackupCodes(userId: string): Promise<BackupCodeSet | null>;
    saveBackupCodes(userId: string, codes: BackupCodeSet): Promise<void>;
    deleteBackupCodes(userId: string): Promise<boolean>;
    getInvitation(token: string): Promise<AdminInvitation | null>;
    getInvitationById(id: string): Promise<AdminInvitation | null>;
    getAllInvitations(): Promise<AdminInvitation[]>;
    getPendingInvitations(): Promise<AdminInvitation[]>;
    createInvitation(invitation: Omit<AdminInvitation, 'id'>): Promise<AdminInvitation>;
    updateInvitation(token: string, updates: Partial<AdminInvitation>): Promise<AdminInvitation>;
    deleteInvitation(token: string): Promise<boolean>;
    cleanupExpiredInvitations(): Promise<number>;
    logAuditEvent(event: Omit<AuditEvent, 'id'>): Promise<AuditEvent>;
    getAuditEvents(filters: AuditEventFilters): Promise<AuditEvent[]>;
    getRecentAuditEvents(limit?: number): Promise<AuditEvent[]>;
}
//# sourceMappingURL=memory.d.ts.map