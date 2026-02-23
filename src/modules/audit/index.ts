







import type { AuditEvent, AuditEventType, AuditSeverity } from '../../types/auth.js';
import type { IStorageAdapter, AuditEventFilters } from '../../storage/interface.js';

export interface AuditLoggerConfig {
  
  storage: IStorageAdapter;
  
  enabled: boolean;
  
  flushInterval?: number;
  
  maxBufferSize?: number;
  
  externalLogger?: (event: AuditEvent) => Promise<void>;
}






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

    
    this.buffer.push(event);

    
    if (this.externalLogger) {
      try {
        await this.externalLogger(event as AuditEvent);
      } catch (error) {
        console.error('[AuditLogger] External logger error:', error);
      }
    }

    
    if (!this.flushTimer) {
      this.flushTimer = setTimeout(() => this.flush(), this.flushInterval);
    }

    
    if (event.severity === 'critical' || this.buffer.length >= this.maxBufferSize) {
      await this.flush();
    }
  }

  


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
      
      this.buffer.unshift(...eventsToWrite);
    }
  }

  


  async query(filters: AuditEventFilters): Promise<AuditEvent[]> {
    return this.storage.getAuditEvents(filters);
  }

  


  async getRecentEvents(limit: number = 100): Promise<AuditEvent[]> {
    return this.storage.getRecentAuditEvents(limit);
  }

  


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

  


  async close(): Promise<void> {
    await this.flush();
  }
}




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




export function createAuditLogger(config: AuditLoggerConfig): AuditLogger {
  return new AuditLogger(config);
}


export { AuditEventType } from '../../types/auth.js';
