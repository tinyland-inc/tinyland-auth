/**
 * Session Manager
 *
 * Framework-agnostic session management with observability metadata.
 *
 * @module @tinyland/auth/core/session
 */
export class SessionManager {
    storage;
    config;
    constructor({ storage, config }) {
        this.storage = storage;
        this.config = config;
    }
    /**
     * Create a new session
     */
    async createSession(userId, user, metadata) {
        // Remove existing sessions for user (single session strategy)
        await this.storage.deleteUserSessions(userId);
        const session = await this.storage.createSession(userId, user, metadata);
        return session;
    }
    /**
     * Get a session by ID
     */
    async getSession(sessionId) {
        if (!sessionId)
            return null;
        const session = await this.storage.getSession(sessionId);
        if (!session)
            return null;
        // Check if expired
        if (new Date(session.expires) < new Date()) {
            await this.storage.deleteSession(sessionId);
            return null;
        }
        return session;
    }
    /**
     * Validate a session
     */
    async validateSession(sessionId) {
        return this.getSession(sessionId);
    }
    /**
     * Update session data
     */
    async updateSession(sessionId, updates) {
        return this.storage.updateSession(sessionId, updates);
    }
    /**
     * Update user data in session
     */
    async updateSessionUser(sessionId, userData) {
        const session = await this.getSession(sessionId);
        if (!session)
            return false;
        const updatedUser = {
            ...session.user,
            ...userData,
            id: session.user?.id || session.userId,
        };
        await this.storage.updateSession(sessionId, { user: updatedUser });
        return true;
    }
    /**
     * Refresh session expiry
     */
    async refreshSession(sessionId) {
        const session = await this.getSession(sessionId);
        if (!session)
            return null;
        const now = new Date();
        const newExpiry = new Date(now.getTime() + this.config.maxAge);
        return this.storage.updateSession(sessionId, {
            expires: newExpiry.toISOString(),
            expiresAt: newExpiry.toISOString(),
        });
    }
    /**
     * Remove a session
     */
    async removeSession(sessionId) {
        return this.storage.deleteSession(sessionId);
    }
    /**
     * Remove all sessions for a user
     */
    async removeUserSessions(userId) {
        return this.storage.deleteUserSessions(userId);
    }
    /**
     * Clean up expired sessions
     */
    async cleanupExpiredSessions() {
        return this.storage.cleanupExpiredSessions();
    }
    /**
     * Get all sessions for a user
     */
    async getUserSessions(userId) {
        return this.storage.getSessionsByUser(userId);
    }
    /**
     * Check if session should be renewed
     */
    shouldRenewSession(session) {
        const expires = new Date(session.expires);
        const now = new Date();
        const remaining = expires.getTime() - now.getTime();
        return remaining < this.config.renewThreshold;
    }
    /**
     * Check if session is valid
     */
    isSessionValid(session) {
        if (!session)
            return false;
        return new Date(session.expires) > new Date();
    }
}
/**
 * Create a session manager instance
 */
export function createSessionManager(storage, config) {
    return new SessionManager({ storage, config });
}
/**
 * Classify device type from user agent
 */
export function classifyDevice(userAgent) {
    const ua = userAgent.toLowerCase();
    if (/mobile|android|iphone|ipod|blackberry|opera mini|iemobile/i.test(ua)) {
        // Check for tablet patterns
        if (/tablet|ipad|android(?!.*mobile)/i.test(ua)) {
            return 'tablet';
        }
        return 'mobile';
    }
    if (/tablet|ipad/i.test(ua)) {
        return 'tablet';
    }
    if (/mozilla|chrome|safari|firefox|edge|opera/i.test(ua)) {
        return 'desktop';
    }
    return 'unknown';
}
/**
 * Extract browser info from user agent
 */
export function extractBrowserInfo(userAgent) {
    const ua = userAgent.toLowerCase();
    let browser = 'Unknown';
    let platform = 'Unknown';
    // Detect browser
    if (ua.includes('firefox'))
        browser = 'Firefox';
    else if (ua.includes('edg'))
        browser = 'Edge';
    else if (ua.includes('chrome'))
        browser = 'Chrome';
    else if (ua.includes('safari'))
        browser = 'Safari';
    else if (ua.includes('opera'))
        browser = 'Opera';
    // Detect platform
    if (ua.includes('windows'))
        platform = 'Windows';
    else if (ua.includes('mac'))
        platform = 'macOS';
    else if (ua.includes('linux'))
        platform = 'Linux';
    else if (ua.includes('android'))
        platform = 'Android';
    else if (ua.includes('iphone') || ua.includes('ipad'))
        platform = 'iOS';
    return { browser, platform };
}
//# sourceMappingURL=index.js.map