/**
 * Storage Adapter Interface
 *
 * Defines the contract for pluggable storage backends.
 * Implementations must handle all CRUD operations for auth entities.
 *
 * @module @tinyland/auth/storage
 */
import type { AdminUser, Session, SessionMetadata, EncryptedTOTPSecret, BackupCodeSet, AdminInvitation, AuditEvent } from '../types/auth.js';
/**
 * Storage adapter interface
 *
 * All methods are async to support both sync (file) and async (database) backends.
 */
export interface IStorageAdapter {
    /**
     * Get a user by ID
     */
    getUser(id: string): Promise<AdminUser | null>;
    /**
     * Get a user by handle (username)
     */
    getUserByHandle(handle: string): Promise<AdminUser | null>;
    /**
     * Get a user by email
     */
    getUserByEmail(email: string): Promise<AdminUser | null>;
    /**
     * Get all users
     */
    getAllUsers(): Promise<AdminUser[]>;
    /**
     * Create a new user
     */
    createUser(user: Omit<AdminUser, 'id'>): Promise<AdminUser>;
    /**
     * Update an existing user
     */
    updateUser(id: string, updates: Partial<AdminUser>): Promise<AdminUser>;
    /**
     * Delete a user
     */
    deleteUser(id: string): Promise<boolean>;
    /**
     * Check if any users exist (for bootstrap detection)
     */
    hasUsers(): Promise<boolean>;
    /**
     * Get a session by ID
     */
    getSession(id: string): Promise<Session | null>;
    /**
     * Get all sessions for a user
     */
    getSessionsByUser(userId: string): Promise<Session[]>;
    /**
     * Get all sessions
     */
    getAllSessions(): Promise<Session[]>;
    /**
     * Create a new session
     */
    createSession(userId: string, user: Partial<AdminUser>, metadata?: SessionMetadata): Promise<Session>;
    /**
     * Update an existing session
     */
    updateSession(id: string, updates: Partial<Session>): Promise<Session>;
    /**
     * Delete a session
     */
    deleteSession(id: string): Promise<boolean>;
    /**
     * Delete all sessions for a user
     */
    deleteUserSessions(userId: string): Promise<number>;
    /**
     * Clean up expired sessions
     */
    cleanupExpiredSessions(): Promise<number>;
    /**
     * Get TOTP secret by handle
     */
    getTOTPSecret(handle: string): Promise<EncryptedTOTPSecret | null>;
    /**
     * Save TOTP secret
     */
    saveTOTPSecret(handle: string, secret: EncryptedTOTPSecret): Promise<void>;
    /**
     * Delete TOTP secret
     */
    deleteTOTPSecret(handle: string): Promise<boolean>;
    /**
     * Get backup codes for a user
     */
    getBackupCodes(userId: string): Promise<BackupCodeSet | null>;
    /**
     * Save backup codes for a user
     */
    saveBackupCodes(userId: string, codes: BackupCodeSet): Promise<void>;
    /**
     * Delete backup codes for a user
     */
    deleteBackupCodes(userId: string): Promise<boolean>;
    /**
     * Get invitation by token
     */
    getInvitation(token: string): Promise<AdminInvitation | null>;
    /**
     * Get invitation by ID
     */
    getInvitationById(id: string): Promise<AdminInvitation | null>;
    /**
     * Get all invitations
     */
    getAllInvitations(): Promise<AdminInvitation[]>;
    /**
     * Get pending invitations
     */
    getPendingInvitations(): Promise<AdminInvitation[]>;
    /**
     * Create a new invitation
     */
    createInvitation(invitation: Omit<AdminInvitation, 'id'>): Promise<AdminInvitation>;
    /**
     * Update an existing invitation
     */
    updateInvitation(token: string, updates: Partial<AdminInvitation>): Promise<AdminInvitation>;
    /**
     * Delete an invitation
     */
    deleteInvitation(token: string): Promise<boolean>;
    /**
     * Clean up expired invitations
     */
    cleanupExpiredInvitations(): Promise<number>;
    /**
     * Log an audit event
     */
    logAuditEvent(event: Omit<AuditEvent, 'id'>): Promise<AuditEvent>;
    /**
     * Get audit events with filters
     */
    getAuditEvents(filters: AuditEventFilters): Promise<AuditEvent[]>;
    /**
     * Get recent audit events
     */
    getRecentAuditEvents(limit?: number): Promise<AuditEvent[]>;
    /**
     * Initialize the storage adapter
     */
    init(): Promise<void>;
    /**
     * Close/cleanup the storage adapter
     */
    close(): Promise<void>;
}
/**
 * Audit event filter options
 */
export interface AuditEventFilters {
    type?: string;
    userId?: string;
    startDate?: Date;
    endDate?: Date;
    severity?: string;
    limit?: number;
    offset?: number;
}
/**
 * Storage adapter configuration
 */
export interface StorageAdapterConfig {
    /** Base path for file storage */
    basePath?: string;
    /** Database connection string */
    connectionString?: string;
    /** Additional options */
    options?: Record<string, unknown>;
}
//# sourceMappingURL=interface.d.ts.map