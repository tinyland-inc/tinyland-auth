/**
 * Activity-Based Session Renewal
 *
 * Tracks user activity and extends session expiry when users are active
 * instead of forcing logout at fixed intervals.
 *
 * Framework-agnostic: uses dependency injection for logging and storage.
 *
 * @module @tinyland/auth/core/session/activity-tracking
 */

import type { Session } from '../../types/auth.js';
import type { IStorageAdapter } from '../../storage/interface.js';

/**
 * Activity event types that should extend session
 */
export type ActivityType =
  | 'page_view'
  | 'api_call'
  | 'websocket_message'
  | 'form_submit'
  | 'click'
  | 'scroll'
  | 'heartbeat';

export interface ActivityEvent {
  sessionId: string;
  userId?: string;
  activityType: ActivityType;
  path?: string;
  metadata?: Record<string, unknown>;
}

/**
 * Configuration for the activity tracker
 */
export interface ActivityTrackingConfig {
  /** Storage adapter for session operations */
  storage: IStorageAdapter;

  /** Optional logger callback (DI pattern, no $lib dependency) */
  logger?: (level: string, message: string, data?: Record<string, unknown>) => void;

  /** Renew session if it will expire in less than this many ms (default: 1 day) */
  renewThresholdMs?: number;

  /** Extend session by this many ms on activity (default: 7 days) */
  renewExtensionMs?: number;

  /** Minimum time between renewals to prevent excessive writes (default: 5 min) */
  minRenewalIntervalMs?: number;

  /** Activity types that should trigger renewal */
  renewalActivities?: Set<ActivityType>;
}

const DEFAULT_RENEWAL_ACTIVITIES = new Set<ActivityType>([
  'page_view',
  'api_call',
  'form_submit',
  'heartbeat',
]);

/**
 * Create an activity tracker instance
 *
 * @example
 * ```typescript
 * const tracker = createActivityTracker({
 *   storage: fileStorageAdapter,
 *   logger: (level, msg, data) => console.log(`[${level}] ${msg}`, data),
 * });
 *
 * await tracker.trackActivityAndRenew({
 *   sessionId: 'abc123',
 *   activityType: 'page_view',
 *   path: '/admin/dashboard',
 * });
 * ```
 */
export function createActivityTracker(config: ActivityTrackingConfig) {
  const {
    storage,
    logger = () => {},
    renewThresholdMs = 24 * 60 * 60 * 1000,
    renewExtensionMs = 7 * 24 * 60 * 60 * 1000,
    minRenewalIntervalMs = 5 * 60 * 1000,
    renewalActivities = DEFAULT_RENEWAL_ACTIVITIES,
  } = config;

  /** Track when sessions were last renewed to prevent excessive writes */
  const lastRenewalMap = new Map<string, number>();

  /**
   * Log activity with session and user tagging for observability
   */
  async function logActivity(activity: ActivityEvent): Promise<void> {
    try {
      logger('info', 'User activity', {
        activity_type: activity.activityType,
        session_id: activity.sessionId,
        user_id: activity.userId,
        path: activity.path,
        metadata: activity.metadata,
      });
    } catch (error) {
      logger('error', 'Failed to log activity', {
        error: error instanceof Error ? error.message : 'Unknown error',
        sessionId: activity.sessionId,
      });
    }
  }

  /**
   * Check if session should be renewed based on activity
   */
  function shouldRenewSession(session: Session): boolean {
    const now = Date.now();
    const expiresAt = new Date(session.expires).getTime();
    const timeUntilExpiry = expiresAt - now;

    if (timeUntilExpiry > renewThresholdMs) {
      return false;
    }

    const lastRenewal = lastRenewalMap.get(session.id);
    if (lastRenewal && now - lastRenewal < minRenewalIntervalMs) {
      return false;
    }

    return true;
  }

  /**
   * Renew session expiry based on user activity
   */
  async function renewSessionOnActivity(sessionId: string): Promise<boolean> {
    try {
      const session = await storage.getSession(sessionId);
      if (!session) {
        logger('debug', 'Cannot renew: session not found', { sessionId });
        return false;
      }

      if (!shouldRenewSession(session)) {
        return false;
      }

      const newExpiry = new Date(Date.now() + renewExtensionMs).toISOString();

      await storage.updateSession(sessionId, {
        expires: newExpiry,
      });

      lastRenewalMap.set(sessionId, Date.now());

      logger('info', 'Session renewed due to activity', {
        sessionId,
        userId: session.userId,
        oldExpiry: session.expires,
        newExpiry,
      });

      return true;
    } catch (error) {
      logger('error', 'Failed to renew session', {
        error: error instanceof Error ? error.message : 'Unknown error',
        sessionId,
      });
      return false;
    }
  }

  /**
   * Track activity and renew session if needed
   */
  async function trackActivityAndRenew(activity: ActivityEvent): Promise<void> {
    await logActivity(activity);

    if (renewalActivities.has(activity.activityType)) {
      await renewSessionOnActivity(activity.sessionId);
    }
  }

  /**
   * Clean up old renewal timestamps (call periodically)
   */
  function cleanupRenewalTracking(): void {
    const now = Date.now();
    const cutoff = now - minRenewalIntervalMs;

    for (const [sessionId, timestamp] of lastRenewalMap.entries()) {
      if (timestamp < cutoff) {
        lastRenewalMap.delete(sessionId);
      }
    }
  }

  return {
    logActivity,
    shouldRenewSession,
    renewSessionOnActivity,
    trackActivityAndRenew,
    cleanupRenewalTracking,
  };
}
