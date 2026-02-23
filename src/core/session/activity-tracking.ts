










import type { Session } from '../../types/auth.js';
import type { IStorageAdapter } from '../../storage/interface.js';




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




export interface ActivityTrackingConfig {
  
  storage: IStorageAdapter;

  
  logger?: (level: string, message: string, data?: Record<string, unknown>) => void;

  
  renewThresholdMs?: number;

  
  renewExtensionMs?: number;

  
  minRenewalIntervalMs?: number;

  
  renewalActivities?: Set<ActivityType>;
}

const DEFAULT_RENEWAL_ACTIVITIES = new Set<ActivityType>([
  'page_view',
  'api_call',
  'form_submit',
  'heartbeat',
]);


















export function createActivityTracker(config: ActivityTrackingConfig) {
  const {
    storage,
    logger = () => {},
    renewThresholdMs = 24 * 60 * 60 * 1000,
    renewExtensionMs = 7 * 24 * 60 * 60 * 1000,
    minRenewalIntervalMs = 5 * 60 * 1000,
    renewalActivities = DEFAULT_RENEWAL_ACTIVITIES,
  } = config;

  
  const lastRenewalMap = new Map<string, number>();

  


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

  


  async function trackActivityAndRenew(activity: ActivityEvent): Promise<void> {
    await logActivity(activity);

    if (renewalActivities.has(activity.activityType)) {
      await renewSessionOnActivity(activity.sessionId);
    }
  }

  


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
