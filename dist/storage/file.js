/**
 * File Storage Adapter
 *
 * Backward-compatible file-based storage for tinyland.dev.
 * Reads/writes JSON files to content/auth/ directory.
 *
 * @module @tinyland/auth/storage/file
 */
import { promises as fs } from 'fs';
import path from 'path';
import { randomBytes, randomUUID } from 'crypto';
const DEFAULT_CONFIG = {
    authDir: 'content/auth',
    totpDir: '.totp-secrets',
    sessionMaxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
};
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
 *
 * Features:
 * - Atomic writes using temp file + rename pattern
 * - File locking for concurrent access safety
 */
export class FileStorageAdapter {
    config;
    basePath;
    /** In-memory lock map to prevent concurrent file access */
    locks = new Map();
    constructor(config = {}) {
        this.config = { ...DEFAULT_CONFIG, ...config };
        this.basePath = process.cwd();
    }
    // ============================================================================
    // Lifecycle
    // ============================================================================
    async init() {
        // Ensure directories exist
        await this.ensureDir(this.getPath('admin-users.json'));
        await this.ensureDir(this.getPath('sessions.json'));
        await this.ensureDir(this.getPath('invites.json'));
        await this.ensureDir(this.getPath('logs/audit.json'));
        await this.ensureDir(path.join(this.basePath, this.config.totpDir, 'backup-codes', '.gitkeep'));
    }
    async close() {
        // No-op for file-based storage
    }
    async hasUsers() {
        const users = await this.readJsonFile(this.getPath('admin-users.json'), []);
        return users.length > 0;
    }
    async getAllSessions() {
        return this.readJsonFile(this.getPath('sessions.json'), []);
    }
    // ============================================================================
    // File Helpers
    // ============================================================================
    getPath(filename) {
        return path.join(this.basePath, this.config.authDir, filename);
    }
    getTotpPath(handle) {
        return path.join(this.basePath, this.config.totpDir, `${handle}.json`);
    }
    getBackupCodesPath(userId) {
        return path.join(this.basePath, this.config.totpDir, 'backup-codes', `${userId}.json`);
    }
    async ensureDir(filePath) {
        const dir = path.dirname(filePath);
        try {
            await fs.access(dir);
        }
        catch {
            await fs.mkdir(dir, { recursive: true });
        }
    }
    async readJsonFile(filePath, defaultValue) {
        try {
            await this.ensureDir(filePath);
            const content = await fs.readFile(filePath, 'utf8');
            return JSON.parse(content);
        }
        catch (error) {
            if (error.code === 'ENOENT') {
                return defaultValue;
            }
            throw error;
        }
    }
    /**
     * Atomically write JSON data to a file using temp file + rename pattern.
     * This prevents partial writes and data corruption on crash.
     */
    async writeJsonFile(filePath, data) {
        await this.withFileLock(filePath, async () => {
            await this.writeJsonFileAtomic(filePath, data);
        });
    }
    /**
     * Internal atomic write implementation using temp file + rename.
     * The rename operation is atomic on POSIX systems.
     */
    async writeJsonFileAtomic(filePath, data) {
        await this.ensureDir(filePath);
        const tempPath = `${filePath}.${Date.now()}.${randomBytes(4).toString('hex')}.tmp`;
        try {
            await fs.writeFile(tempPath, JSON.stringify(data, null, 2), 'utf8');
            await fs.rename(tempPath, filePath); // Atomic on POSIX
        }
        catch (error) {
            // Clean up temp file on failure
            try {
                await fs.unlink(tempPath);
            }
            catch { /* ignore cleanup errors */ }
            throw error;
        }
    }
    /**
     * Execute an operation with an exclusive lock on the given file path.
     * Prevents race conditions when multiple operations target the same file.
     */
    async withFileLock(filePath, operation) {
        // Wait for any existing lock on this file
        const existing = this.locks.get(filePath);
        if (existing) {
            await existing;
        }
        // Create a new lock
        let resolve;
        const lockPromise = new Promise(r => { resolve = r; });
        this.locks.set(filePath, lockPromise);
        try {
            return await operation();
        }
        finally {
            resolve();
            this.locks.delete(filePath);
        }
    }
    // ============================================================================
    // User Operations
    // ============================================================================
    async getUser(id) {
        const users = await this.readJsonFile(this.getPath('admin-users.json'), []);
        return users.find(u => u.id === id) || null;
    }
    async getUserByHandle(handle) {
        const users = await this.readJsonFile(this.getPath('admin-users.json'), []);
        return users.find(u => u.handle === handle) || null;
    }
    async getUserByEmail(email) {
        const users = await this.readJsonFile(this.getPath('admin-users.json'), []);
        return users.find(u => u.email === email) || null;
    }
    async createUser(userData) {
        const users = await this.readJsonFile(this.getPath('admin-users.json'), []);
        const user = {
            id: randomUUID(),
            ...userData,
            createdAt: new Date().toISOString(),
            updatedAt: new Date().toISOString(),
        };
        users.push(user);
        await this.writeJsonFile(this.getPath('admin-users.json'), users);
        return user;
    }
    async updateUser(id, updates) {
        const users = await this.readJsonFile(this.getPath('admin-users.json'), []);
        const index = users.findIndex(u => u.id === id);
        if (index === -1) {
            throw new Error(`User not found: ${id}`);
        }
        users[index] = {
            ...users[index],
            ...updates,
            updatedAt: new Date().toISOString(),
        };
        await this.writeJsonFile(this.getPath('admin-users.json'), users);
        return users[index];
    }
    async deleteUser(id) {
        const users = await this.readJsonFile(this.getPath('admin-users.json'), []);
        const index = users.findIndex(u => u.id === id);
        if (index === -1)
            return false;
        users.splice(index, 1);
        await this.writeJsonFile(this.getPath('admin-users.json'), users);
        return true;
    }
    async getAllUsers() {
        return this.readJsonFile(this.getPath('admin-users.json'), []);
    }
    // ============================================================================
    // Session Operations
    // ============================================================================
    async getSession(id) {
        const sessions = await this.readJsonFile(this.getPath('sessions.json'), []);
        return sessions.find(s => s.id === id) || null;
    }
    async createSession(userId, userData, metadata) {
        const sessions = await this.readJsonFile(this.getPath('sessions.json'), []);
        const now = new Date();
        const expires = new Date(now.getTime() + this.config.sessionMaxAge);
        const session = {
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
        await this.writeJsonFile(this.getPath('sessions.json'), sessions);
        return session;
    }
    async updateSession(id, updates) {
        const sessions = await this.readJsonFile(this.getPath('sessions.json'), []);
        const index = sessions.findIndex(s => s.id === id);
        if (index === -1) {
            throw new Error(`Session not found: ${id}`);
        }
        sessions[index] = { ...sessions[index], ...updates };
        await this.writeJsonFile(this.getPath('sessions.json'), sessions);
        return sessions[index];
    }
    async deleteSession(id) {
        const sessions = await this.readJsonFile(this.getPath('sessions.json'), []);
        const index = sessions.findIndex(s => s.id === id);
        if (index === -1)
            return false;
        sessions.splice(index, 1);
        await this.writeJsonFile(this.getPath('sessions.json'), sessions);
        return true;
    }
    async deleteUserSessions(userId) {
        const sessions = await this.readJsonFile(this.getPath('sessions.json'), []);
        const before = sessions.length;
        const filtered = sessions.filter(s => s.userId !== userId);
        await this.writeJsonFile(this.getPath('sessions.json'), filtered);
        return before - filtered.length;
    }
    async getSessionsByUser(userId) {
        const sessions = await this.readJsonFile(this.getPath('sessions.json'), []);
        return sessions.filter(s => s.userId === userId);
    }
    async cleanupExpiredSessions() {
        const sessions = await this.readJsonFile(this.getPath('sessions.json'), []);
        const now = new Date();
        const before = sessions.length;
        const filtered = sessions.filter(s => new Date(s.expires) > now);
        await this.writeJsonFile(this.getPath('sessions.json'), filtered);
        return before - filtered.length;
    }
    // ============================================================================
    // TOTP Operations
    // ============================================================================
    async getTOTPSecret(handle) {
        try {
            const secret = await this.readJsonFile(this.getTotpPath(handle), null);
            return secret;
        }
        catch {
            return null;
        }
    }
    async saveTOTPSecret(handle, secret) {
        await this.writeJsonFile(this.getTotpPath(handle), secret);
    }
    async deleteTOTPSecret(handle) {
        try {
            await fs.unlink(this.getTotpPath(handle));
            return true;
        }
        catch {
            return false;
        }
    }
    // ============================================================================
    // Backup Codes Operations
    // ============================================================================
    async getBackupCodes(userId) {
        try {
            return await this.readJsonFile(this.getBackupCodesPath(userId), null);
        }
        catch {
            return null;
        }
    }
    async saveBackupCodes(userId, codeSet) {
        await this.writeJsonFile(this.getBackupCodesPath(userId), codeSet);
    }
    async deleteBackupCodes(userId) {
        try {
            await fs.unlink(this.getBackupCodesPath(userId));
            return true;
        }
        catch {
            return false;
        }
    }
    // ============================================================================
    // Invitation Operations
    // ============================================================================
    async getInvitation(token) {
        const invites = await this.readJsonFile(this.getPath('invites.json'), []);
        return invites.find(i => i.token === token) || null;
    }
    async getInvitationById(id) {
        const invites = await this.readJsonFile(this.getPath('invites.json'), []);
        return invites.find(i => i.id === id) || null;
    }
    async createInvitation(data) {
        const invites = await this.readJsonFile(this.getPath('invites.json'), []);
        const invitation = {
            id: randomUUID(),
            ...data,
        };
        invites.push(invitation);
        await this.writeJsonFile(this.getPath('invites.json'), invites);
        return invitation;
    }
    async updateInvitation(token, updates) {
        const invites = await this.readJsonFile(this.getPath('invites.json'), []);
        const index = invites.findIndex(i => i.token === token);
        if (index === -1) {
            throw new Error(`Invitation not found: ${token}`);
        }
        invites[index] = { ...invites[index], ...updates };
        await this.writeJsonFile(this.getPath('invites.json'), invites);
        return invites[index];
    }
    async deleteInvitation(token) {
        const invites = await this.readJsonFile(this.getPath('invites.json'), []);
        const index = invites.findIndex(i => i.token === token);
        if (index === -1)
            return false;
        invites.splice(index, 1);
        await this.writeJsonFile(this.getPath('invites.json'), invites);
        return true;
    }
    async getPendingInvitations() {
        const invites = await this.readJsonFile(this.getPath('invites.json'), []);
        const now = new Date();
        return invites.filter(i => new Date(i.expiresAt) > now && !i.usedAt && i.isActive);
    }
    async getAllInvitations() {
        return this.readJsonFile(this.getPath('invites.json'), []);
    }
    async cleanupExpiredInvitations() {
        const invites = await this.readJsonFile(this.getPath('invites.json'), []);
        const now = new Date();
        const before = invites.length;
        const filtered = invites.filter(i => new Date(i.expiresAt) > now || i.usedAt);
        await this.writeJsonFile(this.getPath('invites.json'), filtered);
        return before - filtered.length;
    }
    // ============================================================================
    // Audit Log Operations
    // ============================================================================
    async logAuditEvent(event) {
        const logPath = this.getPath('logs/audit.json');
        const events = await this.readJsonFile(logPath, []);
        const auditEvent = {
            id: randomUUID(),
            ...event,
        };
        events.push(auditEvent);
        // Keep only last 10000 events
        if (events.length > 10000) {
            events.splice(0, events.length - 10000);
        }
        await this.writeJsonFile(logPath, events);
        return auditEvent;
    }
    async getAuditEvents(filters) {
        const logPath = this.getPath('logs/audit.json');
        let events = await this.readJsonFile(logPath, []);
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
    async getRecentAuditEvents(limit = 100) {
        const logPath = this.getPath('logs/audit.json');
        const events = await this.readJsonFile(logPath, []);
        return events.slice(-limit).reverse();
    }
}
/**
 * Create a file storage adapter instance
 */
export function createFileStorageAdapter(config) {
    return new FileStorageAdapter(config);
}
//# sourceMappingURL=file.js.map