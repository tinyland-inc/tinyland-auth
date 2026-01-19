/**
 * Audit Logger Module
 *
 * Event logging with buffering and severity tracking.
 *
 * @module @tinyland/auth/modules/audit
 */
/**
 * Audit Logger
 *
 * Buffers audit events and flushes to storage periodically.
 */
export class AuditLogger {
    storage;
    enabled;
    buffer = [];
    flushTimer = null;
    flushInterval;
    maxBufferSize;
    externalLogger;
    constructor(config) {
        this.storage = config.storage;
        this.enabled = config.enabled;
        this.flushInterval = config.flushInterval || 1000;
        this.maxBufferSize = config.maxBufferSize || 100;
        this.externalLogger = config.externalLogger;
    }
    /**
     * Log an audit event
     */
    async log(type, details, context) {
        if (!this.enabled)
            return;
        const event = {
            timestamp: new Date().toISOString(),
            type,
            userId: context?.userId,
            targetUserId: context?.targetUserId,
            handle: context?.handle,
            ipAddress: context?.ipAddress,
            userAgent: context?.userAgent,
            details,
            severity: getSeverityForEventType(type),
            source: context?.source || 'system',
        };
        // Add to buffer
        this.buffer.push(event);
        // Send to external logger immediately if configured
        if (this.externalLogger) {
            try {
                await this.externalLogger(event);
            }
            catch (error) {
                console.error('[AuditLogger] External logger error:', error);
            }
        }
        // Schedule flush if not already scheduled
        if (!this.flushTimer) {
            this.flushTimer = setTimeout(() => this.flush(), this.flushInterval);
        }
        // Immediate flush for critical events or if buffer is full
        if (event.severity === 'critical' || this.buffer.length >= this.maxBufferSize) {
            await this.flush();
        }
    }
    /**
     * Flush buffered events to storage
     */
    async flush() {
        if (this.buffer.length === 0)
            return;
        const eventsToWrite = [...this.buffer];
        this.buffer = [];
        if (this.flushTimer) {
            clearTimeout(this.flushTimer);
            this.flushTimer = null;
        }
        try {
            for (const event of eventsToWrite) {
                await this.storage.logAuditEvent(event);
            }
        }
        catch (error) {
            console.error('[AuditLogger] Failed to flush:', error);
            // Re-add events to buffer for retry
            this.buffer.unshift(...eventsToWrite);
        }
    }
    /**
     * Query audit events
     */
    async query(filters) {
        return this.storage.getAuditEvents(filters);
    }
    /**
     * Get recent events
     */
    async getRecentEvents(limit = 100) {
        return this.storage.getRecentAuditEvents(limit);
    }
    /**
     * Get failed login attempts within time window
     */
    async getFailedLoginAttempts(timeWindowMs = 15 * 60 * 1000) {
        const cutoff = new Date(Date.now() - timeWindowMs);
        const events = await this.query({
            type: 'LOGIN_FAILURE',
            startDate: cutoff,
        });
        const attempts = new Map();
        for (const event of events) {
            const key = event.details.handle || event.ipAddress || 'unknown';
            attempts.set(key, (attempts.get(key) || 0) + 1);
        }
        return attempts;
    }
    /**
     * Close the logger
     */
    async close() {
        await this.flush();
    }
}
/**
 * Get severity level for an event type
 */
export function getSeverityForEventType(type) {
    const criticalEvents = [
        'USER_DELETED',
        'ROLE_CHANGED',
        'TOTP_DISABLED',
    ];
    const warningEvents = [
        'ACCOUNT_LOCKED',
        'TOTP_FAILURE',
        'LOGIN_FAILURE',
        'BACKUP_CODE_USED',
    ];
    if (criticalEvents.includes(type))
        return 'critical';
    if (warningEvents.includes(type))
        return 'warning';
    return 'info';
}
/**
 * Create audit logger instance
 */
export function createAuditLogger(config) {
    return new AuditLogger(config);
}
// Re-export AuditEventType for convenience
export { AuditEventType } from '../../types/auth.js';
//# sourceMappingURL=index.js.map