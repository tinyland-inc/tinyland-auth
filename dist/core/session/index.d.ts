/**
 * Session Manager
 *
 * Framework-agnostic session management with observability metadata.
 *
 * @module @tinyland/auth/core/session
 */
import type { Session, SessionMetadata, SessionUser, AdminUser, SessionConfig } from '../../types/index.js';
import type { IStorageAdapter } from '../../storage/interface.js';
export interface SessionManagerConfig {
    storage: IStorageAdapter;
    config: SessionConfig;
}
export declare class SessionManager {
    private storage;
    private config;
    constructor({ storage, config }: SessionManagerConfig);
    /**
     * Create a new session
     */
    createSession(userId: string, user: Partial<AdminUser>, metadata?: SessionMetadata): Promise<Session>;
    /**
     * Get a session by ID
     */
    getSession(sessionId: string): Promise<Session | null>;
    /**
     * Validate a session
     */
    validateSession(sessionId: string): Promise<Session | null>;
    /**
     * Update session data
     */
    updateSession(sessionId: string, updates: Partial<Session>): Promise<Session>;
    /**
     * Update user data in session
     */
    updateSessionUser(sessionId: string, userData: Partial<SessionUser>): Promise<boolean>;
    /**
     * Refresh session expiry
     */
    refreshSession(sessionId: string): Promise<Session | null>;
    /**
     * Remove a session
     */
    removeSession(sessionId: string): Promise<boolean>;
    /**
     * Remove all sessions for a user
     */
    removeUserSessions(userId: string): Promise<number>;
    /**
     * Clean up expired sessions
     */
    cleanupExpiredSessions(): Promise<number>;
    /**
     * Get all sessions for a user
     */
    getUserSessions(userId: string): Promise<Session[]>;
    /**
     * Check if session should be renewed
     */
    shouldRenewSession(session: Session): boolean;
    /**
     * Check if session is valid
     */
    isSessionValid(session: Session | null): session is Session;
}
/**
 * Create a session manager instance
 */
export declare function createSessionManager(storage: IStorageAdapter, config: SessionConfig): SessionManager;
/**
 * Classify device type from user agent
 */
export declare function classifyDevice(userAgent: string): 'mobile' | 'tablet' | 'desktop' | 'unknown';
/**
 * Extract browser info from user agent
 */
export declare function extractBrowserInfo(userAgent: string): {
    browser: string;
    platform: string;
};
//# sourceMappingURL=index.d.ts.map