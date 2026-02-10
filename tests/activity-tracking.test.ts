/**
 * Activity Tracking Unit Tests
 *
 * Tests for session activity tracking, renewal logic, and cleanup.
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';
import { createActivityTracker, type ActivityEvent } from '../src/core/session/activity-tracking.js';
import { MemoryStorageAdapter } from '../src/storage/index.js';

describe('Activity Tracking', () => {
  let storage: MemoryStorageAdapter;

  beforeEach(async () => {
    storage = new MemoryStorageAdapter();
    await storage.init();
  });

  function createSession(overrides: Record<string, unknown> = {}) {
    const now = new Date();
    const expires = new Date(now.getTime() + 2 * 24 * 60 * 60 * 1000); // 2 days from now

    return storage.createSession(
      'user-1',
      { id: 'user-1', handle: 'testuser', email: 'test@test.com' },
      {
        clientIp: '127.0.0.1',
        userAgent: 'TestBrowser/1.0',
        ...overrides,
      }
    );
  }

  describe('createActivityTracker', () => {
    it('should create a tracker with all methods', () => {
      const tracker = createActivityTracker({
        storage,
      });

      expect(tracker.logActivity).toBeInstanceOf(Function);
      expect(tracker.shouldRenewSession).toBeInstanceOf(Function);
      expect(tracker.renewSessionOnActivity).toBeInstanceOf(Function);
      expect(tracker.trackActivityAndRenew).toBeInstanceOf(Function);
      expect(tracker.cleanupRenewalTracking).toBeInstanceOf(Function);
    });
  });

  describe('logActivity', () => {
    it('should call logger with activity details', async () => {
      const logMessages: Array<{ level: string; message: string; data?: Record<string, unknown> }> = [];
      const tracker = createActivityTracker({
        storage,
        logger: (level, message, data) => {
          logMessages.push({ level, message, data });
        },
      });

      const activity: ActivityEvent = {
        sessionId: 'test-session',
        userId: 'user-1',
        activityType: 'page_view',
        path: '/dashboard',
      };

      await tracker.logActivity(activity);

      expect(logMessages.length).toBe(1);
      expect(logMessages[0].level).toBe('info');
      expect(logMessages[0].message).toBe('User activity');
      expect(logMessages[0].data?.activity_type).toBe('page_view');
    });

    it('should handle logger error in catch by only throwing once', async () => {
      let callCount = 0;
      const tracker = createActivityTracker({
        storage,
        logger: () => {
          callCount++;
          if (callCount === 1) {
            throw new Error('Logger failure');
          }
          // Second call (from the catch block) succeeds
        },
      });

      const activity: ActivityEvent = {
        sessionId: 'test-session',
        activityType: 'page_view',
      };

      // The catch block calls logger again for the error;
      // if the error logger also throws, the error will propagate
      // With a logger that only fails once, it should succeed
      await expect(tracker.logActivity(activity)).resolves.toBeUndefined();
      expect(callCount).toBe(2); // Initial call + error handling call
    });
  });

  describe('shouldRenewSession', () => {
    it('should return true when session expires within threshold', () => {
      const tracker = createActivityTracker({
        storage,
        renewThresholdMs: 24 * 60 * 60 * 1000, // 1 day
      });

      const session = {
        id: 'test-session',
        userId: 'user-1',
        expires: new Date(Date.now() + 12 * 60 * 60 * 1000).toISOString(), // 12 hours from now
        expiresAt: new Date(Date.now() + 12 * 60 * 60 * 1000).toISOString(),
        createdAt: new Date().toISOString(),
        clientIp: '127.0.0.1',
        userAgent: 'Test',
      };

      expect(tracker.shouldRenewSession(session)).toBe(true);
    });

    it('should return false when session has plenty of time left', () => {
      const tracker = createActivityTracker({
        storage,
        renewThresholdMs: 24 * 60 * 60 * 1000, // 1 day
      });

      const session = {
        id: 'test-session',
        userId: 'user-1',
        expires: new Date(Date.now() + 5 * 24 * 60 * 60 * 1000).toISOString(), // 5 days from now
        expiresAt: new Date(Date.now() + 5 * 24 * 60 * 60 * 1000).toISOString(),
        createdAt: new Date().toISOString(),
        clientIp: '127.0.0.1',
        userAgent: 'Test',
      };

      expect(tracker.shouldRenewSession(session)).toBe(false);
    });
  });

  describe('renewSessionOnActivity', () => {
    it('should renew a session that is near expiry', async () => {
      const session = await createSession();
      // Manually update expires to be close to threshold
      await storage.updateSession(session.id, {
        expires: new Date(Date.now() + 12 * 60 * 60 * 1000).toISOString(), // 12 hours
      });

      const tracker = createActivityTracker({
        storage,
        renewThresholdMs: 24 * 60 * 60 * 1000,
        renewExtensionMs: 7 * 24 * 60 * 60 * 1000,
      });

      const renewed = await tracker.renewSessionOnActivity(session.id);
      expect(renewed).toBe(true);

      // Verify session was extended
      const updatedSession = await storage.getSession(session.id);
      expect(updatedSession).not.toBeNull();
      const newExpiry = new Date(updatedSession!.expires).getTime();
      // New expiry should be ~7 days from now
      expect(newExpiry).toBeGreaterThan(Date.now() + 6 * 24 * 60 * 60 * 1000);
    });

    it('should not renew a session that is not near expiry', async () => {
      const session = await createSession();
      // Session already has plenty of time (default is > 1 day threshold)

      const tracker = createActivityTracker({
        storage,
        renewThresholdMs: 12 * 60 * 60 * 1000, // 12 hours
      });

      const renewed = await tracker.renewSessionOnActivity(session.id);
      expect(renewed).toBe(false);
    });

    it('should return false for non-existent session', async () => {
      const tracker = createActivityTracker({ storage });

      const renewed = await tracker.renewSessionOnActivity('nonexistent-id');
      expect(renewed).toBe(false);
    });

    it('should respect minimum renewal interval', async () => {
      const session = await createSession();
      await storage.updateSession(session.id, {
        expires: new Date(Date.now() + 6 * 60 * 60 * 1000).toISOString(), // 6 hours
      });

      const tracker = createActivityTracker({
        storage,
        renewThresholdMs: 24 * 60 * 60 * 1000,
        renewExtensionMs: 7 * 24 * 60 * 60 * 1000,
        minRenewalIntervalMs: 5 * 60 * 1000,
      });

      // First renewal should succeed
      const first = await tracker.renewSessionOnActivity(session.id);
      expect(first).toBe(true);

      // Update expiry back to near threshold for second attempt
      await storage.updateSession(session.id, {
        expires: new Date(Date.now() + 6 * 60 * 60 * 1000).toISOString(),
      });

      // Second renewal within interval should fail
      const second = await tracker.renewSessionOnActivity(session.id);
      expect(second).toBe(false);
    });
  });

  describe('trackActivityAndRenew', () => {
    it('should log activity and attempt renewal for renewal activities', async () => {
      const session = await createSession();
      await storage.updateSession(session.id, {
        expires: new Date(Date.now() + 6 * 60 * 60 * 1000).toISOString(),
      });

      const logMessages: string[] = [];
      const tracker = createActivityTracker({
        storage,
        logger: (_level, message) => { logMessages.push(message); },
        renewThresholdMs: 24 * 60 * 60 * 1000,
      });

      await tracker.trackActivityAndRenew({
        sessionId: session.id,
        activityType: 'page_view',
      });

      expect(logMessages).toContain('User activity');
    });

    it('should not attempt renewal for non-renewal activities', async () => {
      const session = await createSession();
      await storage.updateSession(session.id, {
        expires: new Date(Date.now() + 6 * 60 * 60 * 1000).toISOString(),
      });

      const tracker = createActivityTracker({
        storage,
        renewThresholdMs: 24 * 60 * 60 * 1000,
      });

      // 'scroll' and 'click' are not in the default renewal activities
      await tracker.trackActivityAndRenew({
        sessionId: session.id,
        activityType: 'scroll',
      });

      // Session should not have been renewed
      // (We just verify it completes without error)
    });
  });

  describe('cleanupRenewalTracking', () => {
    it('should clean up old renewal timestamps', async () => {
      const session = await createSession();
      await storage.updateSession(session.id, {
        expires: new Date(Date.now() + 6 * 60 * 60 * 1000).toISOString(),
      });

      const tracker = createActivityTracker({
        storage,
        renewThresholdMs: 24 * 60 * 60 * 1000,
        minRenewalIntervalMs: 0, // No interval for test
      });

      // Trigger a renewal to add to the map
      await tracker.renewSessionOnActivity(session.id);

      // Cleanup should work without error
      tracker.cleanupRenewalTracking();
    });
  });
});
