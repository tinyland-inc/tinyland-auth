





import type { AdminRole } from './auth.js';




export type AdminPermission =
  | 'admin.access'
  | 'admin.users.view'
  | 'admin.users.manage'
  | 'admin.users.delete'
  | 'admin.content.view'
  | 'admin.content.manage'
  | 'admin.content.moderate'
  | 'admin.events.view'
  | 'admin.events.manage'
  | 'admin.analytics.view'
  | 'admin.analytics.export'
  | 'admin.settings.view'
  | 'admin.settings.manage'
  | 'admin.security.view'
  | 'admin.security.manage'
  | 'admin.logs.view'
  | 'admin.logs.export';




export const PERMISSIONS = {
  ADMIN_ACCESS: 'admin.access',
  ADMIN_USERS_VIEW: 'admin.users.view',
  ADMIN_USERS_MANAGE: 'admin.users.manage',
  ADMIN_USERS_DELETE: 'admin.users.delete',
  ADMIN_CONTENT_VIEW: 'admin.content.view',
  ADMIN_CONTENT_MANAGE: 'admin.content.manage',
  ADMIN_CONTENT_MODERATE: 'admin.content.moderate',
  ADMIN_EVENTS_VIEW: 'admin.events.view',
  ADMIN_EVENTS_MANAGE: 'admin.events.manage',
  ADMIN_ANALYTICS_VIEW: 'admin.analytics.view',
  ADMIN_ANALYTICS_EXPORT: 'admin.analytics.export',
  ADMIN_SETTINGS_VIEW: 'admin.settings.view',
  ADMIN_SETTINGS_MANAGE: 'admin.settings.manage',
  ADMIN_SECURITY_VIEW: 'admin.security.view',
  ADMIN_SECURITY_MANAGE: 'admin.security.manage',
  ADMIN_LOGS_VIEW: 'admin.logs.view',
  ADMIN_LOGS_EXPORT: 'admin.logs.export',
} as const;




export const ROLE_PERMISSIONS: Record<AdminRole, string[]> = {
  super_admin: Object.values(PERMISSIONS),

  admin: [
    PERMISSIONS.ADMIN_ACCESS,
    PERMISSIONS.ADMIN_USERS_VIEW,
    PERMISSIONS.ADMIN_USERS_MANAGE,
    PERMISSIONS.ADMIN_CONTENT_VIEW,
    PERMISSIONS.ADMIN_CONTENT_MANAGE,
    PERMISSIONS.ADMIN_EVENTS_VIEW,
    PERMISSIONS.ADMIN_EVENTS_MANAGE,
    PERMISSIONS.ADMIN_ANALYTICS_VIEW,
    PERMISSIONS.ADMIN_SETTINGS_VIEW,
    PERMISSIONS.ADMIN_LOGS_VIEW,
  ],

  editor: [
    PERMISSIONS.ADMIN_ACCESS,
    PERMISSIONS.ADMIN_CONTENT_VIEW,
    PERMISSIONS.ADMIN_CONTENT_MANAGE,
    PERMISSIONS.ADMIN_ANALYTICS_VIEW,
  ],

  event_manager: [
    PERMISSIONS.ADMIN_ACCESS,
    PERMISSIONS.ADMIN_EVENTS_VIEW,
    PERMISSIONS.ADMIN_EVENTS_MANAGE,
    PERMISSIONS.ADMIN_ANALYTICS_VIEW,
  ],

  moderator: [
    PERMISSIONS.ADMIN_ACCESS,
    PERMISSIONS.ADMIN_CONTENT_VIEW,
    PERMISSIONS.ADMIN_CONTENT_MODERATE,
    PERMISSIONS.ADMIN_USERS_VIEW,
    PERMISSIONS.ADMIN_ANALYTICS_VIEW,
    PERMISSIONS.ADMIN_LOGS_VIEW,
  ],

  contributor: [
    PERMISSIONS.ADMIN_ACCESS,
    PERMISSIONS.ADMIN_CONTENT_VIEW,
  ],

  member: [
    PERMISSIONS.ADMIN_ACCESS,
    PERMISSIONS.ADMIN_CONTENT_VIEW,
    PERMISSIONS.ADMIN_EVENTS_VIEW,
  ],

  viewer: [
    PERMISSIONS.ADMIN_ACCESS,
    PERMISSIONS.ADMIN_ANALYTICS_VIEW,
  ],
};




export type ContentVisibility = 'public' | 'members' | 'admin' | 'private';




export const VALIDATION_RULES = {
  username: {
    pattern: /^[a-zA-Z0-9_-]{3,20}$/,
    minLength: 3,
    maxLength: 20,
    message: 'Username must be 3-20 characters, alphanumeric with _ or -',
  },
  handle: {
    pattern: /^[a-zA-Z0-9_-]{3,20}$/,
    minLength: 3,
    maxLength: 20,
    message: 'Handle must be 3-20 characters, alphanumeric with _ or -',
  },
  password: {
    minLength: 12,
    requireUppercase: true,
    requireLowercase: true,
    requireNumber: true,
    requireSpecial: true,
    message: 'Password must be at least 12 characters with uppercase, lowercase, number, and special character',
  },
} as const;
