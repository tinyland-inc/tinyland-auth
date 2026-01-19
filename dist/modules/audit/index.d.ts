/**
 * Audit Logger Module
 *
 * Event logging with buffering and severity tracking.
 *
 * @module @tinyland/auth/modules/audit
 */
import type { AuditEvent, AuditEventType, AuditSeverity } from '../../types/auth.js';
import type { IStorageAdapter, AuditEventFilters } from '../../storage/interface.js';
export interface AuditLoggerConfig {
    /** Storage adapter */
    storage: IStorageAdapter;
    /** Enable audit logging */
    enabled: boolean;
    /** Flush interval in milliseconds */
    flushInterval?: number;
    /** Maximum buffer size before auto-flush */
    maxBufferSize?: number;
    /** Custom logger for external integrations */
    externalLogger?: (event: AuditEvent) => Promise<void>;
}
/**
 * Audit Logger
 *
 * Buffers audit events and flushes to storage periodically.
 */
export declare class AuditLogger {
    private storage;
    private enabled;
    private buffer;
    private flushTimer;
    private flushInterval;
    private maxBufferSize;
    private externalLogger?;
    constructor(config: AuditLoggerConfig);
    /**
     * Log an audit event
     */
    log(type: AuditEventType, details: Record<string, unknown>, context?: {
        userId?: string;
        targetUserId?: string;
        handle?: string;
        ipAddress?: string;
        userAgent?: string;
        source?: 'system' | 'user' | 'admin';
    }): Promise<void>;
    /**
     * Flush buffered events to storage
     */
    flush(): Promise<void>;
    /**
     * Query audit events
     */
    query(filters: AuditEventFilters): Promise<AuditEvent[]>;
    /**
     * Get recent events
     */
    getRecentEvents(limit?: number): Promise<AuditEvent[]>;
    /**
     * Get failed login attempts within time window
     */
    getFailedLoginAttempts(timeWindowMs?: number): Promise<Map<string, number>>;
    /**
     * Close the logger
     */
    close(): Promise<void>;
}
/**
 * Get severity level for an event type
 */
export declare function getSeverityForEventType(type: AuditEventType): AuditSeverity;
/**
 * Create audit logger instance
 */
export declare function createAuditLogger(config: AuditLoggerConfig): AuditLogger;
export { AuditEventType } from '../../types/auth.js';
//# sourceMappingURL=index.d.ts.map