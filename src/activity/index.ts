/**
 * Activity Tracking Sub-entry Point
 *
 * Re-exports activity tracking from core/session module.
 *
 * @module @tummycrypt/tinyland-auth/activity
 */

export {
  createActivityTracker,
  type ActivityTrackingConfig,
  type ActivityType,
  type ActivityEvent,
} from '../core/session/activity-tracking.js';
