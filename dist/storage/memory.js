/**
 * In-Memory Storage Adapter
 *
 * A simple in-memory storage implementation for testing and development.
 * Data is lost when the process ends.
 *
 * @module @tinyland/auth/storage/memory
 */
import { randomUUID } from 'crypto';
export class MemoryStorageAdapter {
    users = new Map();
    usersByHandle = new Map(); // handle -> id
    usersByEmail = new Map(); // email -> id
    sessions = new Map();
    totpSecrets = new Map();
    backupCodes = new Map();
    invitations = new Map();
    auditEvents = [];
    async init() {
        // No initialization needed for memory adapter
    }
    async close() {
        // Clear all data
        this.users.clear();
        this.usersByHandle.clear();
        this.usersByEmail.clear();
        this.sessions.clear();
        this.totpSecrets.clear();
        this.backupCodes.clear();
        this.invitations.clear();
        this.auditEvents = [];
    }
    // ============================================================================
    // User Operations
    // ============================================================================
    async getUser(id) {
        return this.users.get(id) || null;
    }
    async getUserByHandle(handle) {
        const userId = this.usersByHandle.get(handle.toLowerCase());
        if (!userId)
            return null;
        return this.users.get(userId) || null;
    }
    async getUserByEmail(email) {
        const userId = this.usersByEmail.get(email.toLowerCase());
        if (!userId)
            return null;
        return this.users.get(userId) || null;
    }
    async getAllUsers() {
        return Array.from(this.users.values());
    }
    async createUser(user) {
        const id = randomUUID();
        const newUser = { ...user, id };
        this.users.set(id, newUser);
        this.usersByHandle.set(newUser.handle.toLowerCase(), id);
        if (newUser.email) {
            this.usersByEmail.set(newUser.email.toLowerCase(), id);
        }
        return newUser;
    }
    async updateUser(id, updates) {
        const user = this.users.get(id);
        if (!user) {
            throw new Error(`User ${id} not found`);
        }
        // Handle handle/email index updates
        if (updates.handle && updates.handle !== user.handle) {
            this.usersByHandle.delete(user.handle.toLowerCase());
            this.usersByHandle.set(updates.handle.toLowerCase(), id);
        }
        if (updates.email && updates.email !== user.email) {
            if (user.email) {
                this.usersByEmail.delete(user.email.toLowerCase());
            }
            this.usersByEmail.set(updates.email.toLowerCase(), id);
        }
        const updatedUser = {
            ...user,
            ...updates,
            id, // Ensure ID is not changed
            updatedAt: new Date().toISOString(),
        };
        this.users.set(id, updatedUser);
        return updatedUser;
    }
    async deleteUser(id) {
        const user = this.users.get(id);
        if (!user)
            return false;
        this.users.delete(id);
        this.usersByHandle.delete(user.handle.toLowerCase());
        if (user.email) {
            this.usersByEmail.delete(user.email.toLowerCase());
        }
        // Clean up related data
        await this.deleteUserSessions(id);
        await this.deleteTOTPSecret(user.handle);
        await this.deleteBackupCodes(id);
        return true;
    }
    async hasUsers() {
        return this.users.size > 0;
    }
    // ============================================================================
    // Session Operations
    // ============================================================================
    async getSession(id) {
        const session = this.sessions.get(id);
        if (!session)
            return null;
        // Check expiration
        if (new Date(session.expires) < new Date()) {
            this.sessions.delete(id);
            return null;
        }
        return session;
    }
    async getSessionsByUser(userId) {
        const now = new Date();
        return Array.from(this.sessions.values())
            .filter(s => s.userId === userId && new Date(s.expires) > now);
    }
    async getAllSessions() {
        return Array.from(this.sessions.values());
    }
    async createSession(userId, user, metadata) {
        const id = randomUUID();
        const now = new Date();
        const expires = new Date(now.getTime() + 7 * 24 * 60 * 60 * 1000); // 7 days
        const session = {
            id,
            userId,
            expires: expires.toISOString(),
            expiresAt: expires.toISOString(),
            createdAt: now.toISOString(),
            user: {
                id: user.id || userId,
                username: user.handle || '',
                name: user.displayName || user.handle || '',
                role: user.role || 'viewer',
                needsOnboarding: user.needsOnboarding,
                onboardingStep: user.onboardingStep,
            },
            clientIp: metadata?.clientIp || 'unknown',
            clientIpMasked: metadata?.clientIpMasked,
            userAgent: metadata?.userAgent || 'unknown',
            deviceType: metadata?.deviceType || 'unknown',
            browserFingerprint: metadata?.browserFingerprint,
            geoLocation: metadata?.geoLocation,
        };
        this.sessions.set(id, session);
        return session;
    }
    async updateSession(id, updates) {
        const session = this.sessions.get(id);
        if (!session) {
            throw new Error(`Session ${id} not found`);
        }
        const updatedSession = {
            ...session,
            ...updates,
            id, // Ensure ID is not changed
        };
        this.sessions.set(id, updatedSession);
        return updatedSession;
    }
    async deleteSession(id) {
        return this.sessions.delete(id);
    }
    async deleteUserSessions(userId) {
        let count = 0;
        for (const [id, session] of this.sessions.entries()) {
            if (session.userId === userId) {
                this.sessions.delete(id);
                count++;
            }
        }
        return count;
    }
    async cleanupExpiredSessions() {
        const now = new Date();
        let count = 0;
        for (const [id, session] of this.sessions.entries()) {
            if (new Date(session.expires) < now) {
                this.sessions.delete(id);
                count++;
            }
        }
        return count;
    }
    // ============================================================================
    // TOTP Operations
    // ============================================================================
    async getTOTPSecret(handle) {
        return this.totpSecrets.get(handle.toLowerCase()) || null;
    }
    async saveTOTPSecret(handle, secret) {
        this.totpSecrets.set(handle.toLowerCase(), secret);
    }
    async deleteTOTPSecret(handle) {
        return this.totpSecrets.delete(handle.toLowerCase());
    }
    // ============================================================================
    // Backup Code Operations
    // ============================================================================
    async getBackupCodes(userId) {
        return this.backupCodes.get(userId) || null;
    }
    async saveBackupCodes(userId, codes) {
        this.backupCodes.set(userId, codes);
    }
    async deleteBackupCodes(userId) {
        return this.backupCodes.delete(userId);
    }
    // ============================================================================
    // Invitation Operations
    // ============================================================================
    async getInvitation(token) {
        const invitation = this.invitations.get(token);
        if (!invitation)
            return null;
        // Check expiration
        if (new Date(invitation.expiresAt) < new Date()) {
            return null;
        }
        return invitation;
    }
    async getInvitationById(id) {
        for (const invitation of this.invitations.values()) {
            if (invitation.id === id) {
                return invitation;
            }
        }
        return null;
    }
    async getAllInvitations() {
        return Array.from(this.invitations.values());
    }
    async getPendingInvitations() {
        const now = new Date();
        return Array.from(this.invitations.values())
            .filter(i => new Date(i.expiresAt) > now && !i.usedAt);
    }
    async createInvitation(invitation) {
        const id = randomUUID();
        const newInvitation = { ...invitation, id };
        this.invitations.set(invitation.token, newInvitation);
        return newInvitation;
    }
    async updateInvitation(token, updates) {
        const invitation = this.invitations.get(token);
        if (!invitation) {
            throw new Error(`Invitation not found`);
        }
        const updatedInvitation = {
            ...invitation,
            ...updates,
        };
        this.invitations.set(token, updatedInvitation);
        return updatedInvitation;
    }
    async deleteInvitation(token) {
        return this.invitations.delete(token);
    }
    async cleanupExpiredInvitations() {
        const now = new Date();
        let count = 0;
        for (const [token, invitation] of this.invitations.entries()) {
            if (new Date(invitation.expiresAt) < now || invitation.usedAt) {
                this.invitations.delete(token);
                count++;
            }
        }
        return count;
    }
    // ============================================================================
    // Audit Operations
    // ============================================================================
    async logAuditEvent(event) {
        const id = `evt_${Date.now()}_${Math.random().toString(36).substring(2, 9)}`;
        const auditEvent = { ...event, id };
        this.auditEvents.push(auditEvent);
        // Keep only last 10000 events
        if (this.auditEvents.length > 10000) {
            this.auditEvents = this.auditEvents.slice(-10000);
        }
        return auditEvent;
    }
    async getAuditEvents(filters) {
        let events = [...this.auditEvents];
        if (filters.type) {
            events = events.filter(e => e.type === filters.type);
        }
        if (filters.userId) {
            events = events.filter(e => e.userId === filters.userId);
        }
        if (filters.severity) {
            events = events.filter(e => e.severity === filters.severity);
        }
        if (filters.startDate) {
            events = events.filter(e => new Date(e.timestamp) >= filters.startDate);
        }
        if (filters.endDate) {
            events = events.filter(e => new Date(e.timestamp) <= filters.endDate);
        }
        if (filters.offset) {
            events = events.slice(filters.offset);
        }
        if (filters.limit) {
            events = events.slice(0, filters.limit);
        }
        return events;
    }
    async getRecentAuditEvents(limit = 100) {
        return this.auditEvents.slice(-limit).reverse();
    }
}
//# sourceMappingURL=memory.js.map