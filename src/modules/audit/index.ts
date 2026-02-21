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
export class AuditLogger {
  private storage: IStorageAdapter;
  private enabled: boolean;
  private buffer: Omit<AuditEvent, 'id'>[] = [];
  private flushTimer: ReturnType<typeof setTimeout> | null = null;
  private flushInterval: number;
  private maxBufferSize: number;
  private externalLogger?: (event: AuditEvent) => Promise<void>;

  constructor(config: AuditLoggerConfig) {
    this.storage = config.storage;
    this.enabled = config.enabled;
    this.flushInterval = config.flushInterval || 1000;
    this.maxBufferSize = config.maxBufferSize || 100;
    this.externalLogger = config.externalLogger;
  }

  /**
   * Log an audit event
   */
  async log(
    type: AuditEventType,
    details: Record<string, unknown>,
    context?: {
      userId?: string;
      targetUserId?: string;
      handle?: string;
      ipAddress?: string;
      userAgent?: string;
      source?: 'system' | 'user' | 'admin';
    }
  ): Promise<void> {
    if (!this.enabled) return;

    const event: Omit<AuditEvent, 'id'> = {
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
        await this.externalLogger(event as AuditEvent);
      } catch (error) {
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
  async flush(): Promise<void> {
    if (this.buffer.length === 0) return;

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
    } catch (error) {
      console.error('[AuditLogger] Failed to flush:', error);
      // Re-add events to buffer for retry
      this.buffer.unshift(...eventsToWrite);
    }
  }

  /**
   * Query audit events
   */
  async query(filters: AuditEventFilters): Promise<AuditEvent[]> {
    return this.storage.getAuditEvents(filters);
  }

  /**
   * Get recent events
   */
  async getRecentEvents(limit: number = 100): Promise<AuditEvent[]> {
    return this.storage.getRecentAuditEvents(limit);
  }

  /**
   * Get failed login attempts within time window
   */
  async getFailedLoginAttempts(
    timeWindowMs: number = 15 * 60 * 1000
  ): Promise<Map<string, number>> {
    const cutoff = new Date(Date.now() - timeWindowMs);
    const events = await this.query({
      type: 'LOGIN_FAILURE',
      startDate: cutoff,
    });

    const attempts = new Map<string, number>();
    for (const event of events) {
      const key = (event.details.handle as string) || event.ipAddress || 'unknown';
      attempts.set(key, (attempts.get(key) || 0) + 1);
    }

    return attempts;
  }

  /**
   * Close the logger
   */
  async close(): Promise<void> {
    await this.flush();
  }
}

/**
 * Get severity level for an event type
 */
export function getSeverityForEventType(type: AuditEventType): AuditSeverity {
  const criticalEvents: AuditEventType[] = [
    'USER_DELETED' as AuditEventType,
    'ROLE_CHANGED' as AuditEventType,
    'TOTP_DISABLED' as AuditEventType,
  ];

  const warningEvents: AuditEventType[] = [
    'ACCOUNT_LOCKED' as AuditEventType,
    'TOTP_FAILURE' as AuditEventType,
    'LOGIN_FAILURE' as AuditEventType,
    'BACKUP_CODE_USED' as AuditEventType,
  ];

  if (criticalEvents.includes(type)) return 'critical';
  if (warningEvents.includes(type)) return 'warning';
  return 'info';
}

/**
 * Create audit logger instance
 */
export function createAuditLogger(config: AuditLoggerConfig): AuditLogger {
  return new AuditLogger(config);
}

// Re-export AuditEventType for convenience
export { AuditEventType } from '../../types/auth.js';
