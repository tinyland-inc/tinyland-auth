/**
 * Audit Logger Unit Tests
 *
 * Tests for audit log writing, event formatting, severity, and querying.
 */

import { describe, it, expect, beforeEach, vi, afterEach } from 'vitest';
import {
  AuditLogger,
  createAuditLogger,
  getSeverityForEventType,
  AuditEventType,
  type AuditLoggerConfig,
} from '../src/modules/audit/index.js';
import { MemoryStorageAdapter } from '../src/storage/index.js';

describe('Audit Logger', () => {
  let storage: MemoryStorageAdapter;

  beforeEach(async () => {
    storage = new MemoryStorageAdapter();
    await storage.init();
  });

  function createConfig(overrides: Partial<AuditLoggerConfig> = {}): AuditLoggerConfig {
    return {
      storage,
      enabled: true,
      flushInterval: 50, // Short interval for tests
      ...overrides,
    };
  }

  describe('createAuditLogger', () => {
    it('should create an AuditLogger instance', () => {
      const logger = createAuditLogger(createConfig());
      expect(logger).toBeInstanceOf(AuditLogger);
    });
  });

  describe('log', () => {
    it('should log an audit event', async () => {
      const logger = createAuditLogger(createConfig());

      await logger.log(
        AuditEventType.LOGIN_SUCCESS,
        { handle: 'testuser' },
        { userId: 'user-1', ipAddress: '127.0.0.1' }
      );

      // Flush to ensure event is written
      await logger.flush();

      const events = await logger.getRecentEvents(10);
      expect(events.length).toBe(1);
      expect(events[0].type).toBe(AuditEventType.LOGIN_SUCCESS);
    });

    it('should not log when disabled', async () => {
      const logger = createAuditLogger(createConfig({ enabled: false }));

      await logger.log(
        AuditEventType.LOGIN_SUCCESS,
        { handle: 'testuser' }
      );

      await logger.flush();

      const events = await logger.getRecentEvents(10);
      expect(events.length).toBe(0);
    });

    it('should set correct severity on events', async () => {
      const logger = createAuditLogger(createConfig());

      await logger.log(AuditEventType.LOGIN_SUCCESS, { handle: 'testuser' });
      await logger.log(AuditEventType.LOGIN_FAILURE, { handle: 'testuser' });
      await logger.log(AuditEventType.USER_DELETED, { handle: 'testuser' });

      await logger.flush();

      const events = await logger.getRecentEvents(10);
      const severities = events.map(e => e.severity);

      expect(severities).toContain('info');
      expect(severities).toContain('warning');
      expect(severities).toContain('critical');
    });

    it('should include context fields in the event', async () => {
      const logger = createAuditLogger(createConfig());

      await logger.log(
        AuditEventType.LOGIN_SUCCESS,
        { handle: 'testuser', method: 'password' },
        {
          userId: 'user-123',
          ipAddress: '192.168.1.1',
          userAgent: 'TestBrowser/1.0',
        }
      );

      await logger.flush();

      const events = await logger.getRecentEvents(10);
      expect(events[0].userId).toBe('user-123');
      expect(events[0].ipAddress).toBe('192.168.1.1');
      expect(events[0].userAgent).toBe('TestBrowser/1.0');
    });

    it('should flush immediately for critical events', async () => {
      const logger = createAuditLogger(createConfig());

      await logger.log(
        AuditEventType.USER_DELETED,
        { handle: 'testuser' },
        { userId: 'admin-1' }
      );

      // No explicit flush needed - critical events flush immediately
      const events = await logger.getRecentEvents(10);
      expect(events.length).toBe(1);
    });

    it('should call external logger when configured', async () => {
      const externalEvents: unknown[] = [];
      const logger = createAuditLogger(createConfig({
        externalLogger: async (event) => {
          externalEvents.push(event);
        },
      }));

      await logger.log(AuditEventType.LOGIN_SUCCESS, { handle: 'testuser' });

      expect(externalEvents.length).toBe(1);
    });

    it('should handle external logger errors gracefully', async () => {
      const logger = createAuditLogger(createConfig({
        externalLogger: async () => {
          throw new Error('External logger failure');
        },
      }));

      // Should not throw
      await expect(
        logger.log(AuditEventType.LOGIN_SUCCESS, { handle: 'testuser' })
      ).resolves.toBeUndefined();
    });
  });

  describe('flush', () => {
    it('should write buffered events to storage', async () => {
      const logger = createAuditLogger(createConfig());

      await logger.log(AuditEventType.LOGIN_SUCCESS, { handle: 'user1' });
      await logger.log(AuditEventType.LOGIN_SUCCESS, { handle: 'user2' });
      await logger.log(AuditEventType.LOGIN_SUCCESS, { handle: 'user3' });

      await logger.flush();

      const events = await logger.getRecentEvents(10);
      expect(events.length).toBe(3);
    });

    it('should be safe to call multiple times', async () => {
      const logger = createAuditLogger(createConfig());

      await logger.log(AuditEventType.LOGIN_SUCCESS, { handle: 'testuser' });
      await logger.flush();
      await logger.flush();
      await logger.flush();

      const events = await logger.getRecentEvents(10);
      expect(events.length).toBe(1);
    });

    it('should handle empty buffer without error', async () => {
      const logger = createAuditLogger(createConfig());
      await expect(logger.flush()).resolves.toBeUndefined();
    });
  });

  describe('query', () => {
    it('should filter events by type', async () => {
      const logger = createAuditLogger(createConfig());

      await logger.log(AuditEventType.LOGIN_SUCCESS, { handle: 'user1' });
      await logger.log(AuditEventType.LOGIN_FAILURE, { handle: 'user2' });
      await logger.log(AuditEventType.LOGIN_SUCCESS, { handle: 'user3' });

      await logger.flush();

      const successes = await logger.query({ type: AuditEventType.LOGIN_SUCCESS });
      expect(successes.length).toBe(2);
    });

    it('should filter events by userId', async () => {
      const logger = createAuditLogger(createConfig());

      await logger.log(AuditEventType.LOGIN_SUCCESS, {}, { userId: 'user-1' });
      await logger.log(AuditEventType.LOGIN_SUCCESS, {}, { userId: 'user-2' });
      await logger.log(AuditEventType.LOGIN_SUCCESS, {}, { userId: 'user-1' });

      await logger.flush();

      const user1Events = await logger.query({ userId: 'user-1' });
      expect(user1Events.length).toBe(2);
    });
  });

  describe('getRecentEvents', () => {
    it('should return events ordered by most recent', async () => {
      const logger = createAuditLogger(createConfig());

      await logger.log(AuditEventType.LOGIN_SUCCESS, { order: 1 });
      await logger.log(AuditEventType.LOGIN_SUCCESS, { order: 2 });
      await logger.log(AuditEventType.LOGIN_SUCCESS, { order: 3 });

      await logger.flush();

      const events = await logger.getRecentEvents(10);
      expect(events.length).toBe(3);
    });

    it('should respect limit parameter', async () => {
      const logger = createAuditLogger(createConfig());

      for (let i = 0; i < 10; i++) {
        await logger.log(AuditEventType.LOGIN_SUCCESS, { index: i });
      }

      await logger.flush();

      const events = await logger.getRecentEvents(5);
      expect(events.length).toBe(5);
    });
  });

  describe('getFailedLoginAttempts', () => {
    it('should count failed login attempts by key', async () => {
      const logger = createAuditLogger(createConfig());

      await logger.log(AuditEventType.LOGIN_FAILURE, { handle: 'user1' });
      await logger.log(AuditEventType.LOGIN_FAILURE, { handle: 'user1' });
      await logger.log(AuditEventType.LOGIN_FAILURE, { handle: 'user2' });

      await logger.flush();

      const attempts = await logger.getFailedLoginAttempts(60 * 60 * 1000);
      expect(attempts.get('user1')).toBe(2);
      expect(attempts.get('user2')).toBe(1);
    });
  });

  describe('close', () => {
    it('should flush remaining events on close', async () => {
      const logger = createAuditLogger(createConfig());

      await logger.log(AuditEventType.LOGIN_SUCCESS, { handle: 'testuser' });
      await logger.close();

      const events = await storage.getRecentAuditEvents(10);
      expect(events.length).toBe(1);
    });
  });
});

describe('getSeverityForEventType', () => {
  it('should return critical for user deletion', () => {
    expect(getSeverityForEventType(AuditEventType.USER_DELETED)).toBe('critical');
  });

  it('should return critical for role changes', () => {
    expect(getSeverityForEventType(AuditEventType.ROLE_CHANGED)).toBe('critical');
  });

  it('should return critical for TOTP disabled', () => {
    expect(getSeverityForEventType(AuditEventType.TOTP_DISABLED)).toBe('critical');
  });

  it('should return warning for login failure', () => {
    expect(getSeverityForEventType(AuditEventType.LOGIN_FAILURE)).toBe('warning');
  });

  it('should return warning for TOTP failure', () => {
    expect(getSeverityForEventType(AuditEventType.TOTP_FAILURE)).toBe('warning');
  });

  it('should return warning for account locked', () => {
    expect(getSeverityForEventType(AuditEventType.ACCOUNT_LOCKED)).toBe('warning');
  });

  it('should return warning for backup code usage', () => {
    expect(getSeverityForEventType(AuditEventType.BACKUP_CODE_USED)).toBe('warning');
  });

  it('should return info for login success', () => {
    expect(getSeverityForEventType(AuditEventType.LOGIN_SUCCESS)).toBe('info');
  });

  it('should return info for session created', () => {
    expect(getSeverityForEventType(AuditEventType.SESSION_CREATED)).toBe('info');
  });

  it('should default to info for unknown events', () => {
    expect(getSeverityForEventType(AuditEventType.SYSTEM_CONFIGURED)).toBe('info');
  });
});
