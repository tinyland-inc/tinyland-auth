/**
 * Audit Sub-entry Point
 *
 * Re-exports the audit logger from modules/audit.
 *
 * @module @tummycrypt/tinyland-auth/audit
 */

export {
  AuditLogger,
  createAuditLogger,
  getSeverityForEventType,
  AuditEventType,
  type AuditLoggerConfig,
} from '../modules/audit/index.js';

// Types
export type { AuditEvent, AuditSeverity } from '../types/auth.js';
export type { AuditEventFilters } from '../storage/interface.js';
