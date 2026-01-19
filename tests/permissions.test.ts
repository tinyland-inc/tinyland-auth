/**
 * Permission Functions Unit Tests
 *
 * Tests for RBAC permission system.
 */

import { describe, it, expect } from 'vitest';
import {
  hasPermission,
  hasAnyPermission,
  hasAllPermissions,
  getRolePermissions,
  canManageRole,
  canViewContent,
  filterContentByVisibility,
  getAllowedVisibilityOptions,
  isMemberRole,
} from '../src/core/permissions/index.js';
import { PERMISSIONS } from '../src/types/permissions.js';
import type { AdminUser } from '../src/types/auth.js';

// Test users for various roles
const createTestUser = (role: string, id = 'user-1'): AdminUser => ({
  id,
  handle: `test_${role}`,
  email: `${role}@test.com`,
  passwordHash: 'hash',
  totpEnabled: false,
  role: role as AdminUser['role'],
  isActive: true,
  needsOnboarding: false,
  onboardingStep: 0,
  createdAt: new Date().toISOString(),
  updatedAt: new Date().toISOString(),
});

const superAdmin = createTestUser('super_admin');
const admin = createTestUser('admin');
const moderator = createTestUser('moderator');
const editor = createTestUser('editor');
const eventManager = createTestUser('event_manager');
const contributor = createTestUser('contributor');
const member = createTestUser('member');
const viewer = createTestUser('viewer');

describe('Permission Functions', () => {
  describe('hasPermission', () => {
    it('should return true for super_admin with any permission', () => {
      expect(hasPermission(superAdmin, PERMISSIONS.ADMIN_ACCESS)).toBe(true);
      expect(hasPermission(superAdmin, PERMISSIONS.ADMIN_USERS_MANAGE)).toBe(true);
      expect(hasPermission(superAdmin, PERMISSIONS.ADMIN_SECURITY_MANAGE)).toBe(true);
    });

    it('should return true for admin with user management', () => {
      expect(hasPermission(admin, PERMISSIONS.ADMIN_USERS_VIEW)).toBe(true);
      expect(hasPermission(admin, PERMISSIONS.ADMIN_USERS_MANAGE)).toBe(true);
    });

    it('should return false for viewer with user management permissions', () => {
      expect(hasPermission(viewer, PERMISSIONS.ADMIN_USERS_MANAGE)).toBe(false);
      expect(hasPermission(viewer, PERMISSIONS.ADMIN_CONTENT_MANAGE)).toBe(false);
    });

    it('should return true for viewer with admin access', () => {
      expect(hasPermission(viewer, PERMISSIONS.ADMIN_ACCESS)).toBe(true);
      expect(hasPermission(viewer, PERMISSIONS.ADMIN_ANALYTICS_VIEW)).toBe(true);
    });

    it('should return true for editor with content permissions', () => {
      expect(hasPermission(editor, PERMISSIONS.ADMIN_CONTENT_VIEW)).toBe(true);
      expect(hasPermission(editor, PERMISSIONS.ADMIN_CONTENT_MANAGE)).toBe(true);
    });
  });

  describe('hasAnyPermission', () => {
    it('should return true if user has at least one permission', () => {
      expect(hasAnyPermission(editor, [PERMISSIONS.ADMIN_CONTENT_MANAGE, PERMISSIONS.ADMIN_USERS_MANAGE])).toBe(true);
      expect(hasAnyPermission(viewer, [PERMISSIONS.ADMIN_ACCESS, PERMISSIONS.ADMIN_USERS_MANAGE])).toBe(true);
    });

    it('should return false if user has none of the permissions', () => {
      expect(hasAnyPermission(viewer, [PERMISSIONS.ADMIN_USERS_MANAGE, PERMISSIONS.ADMIN_CONTENT_MANAGE])).toBe(false);
    });
  });

  describe('hasAllPermissions', () => {
    it('should return true if user has all permissions', () => {
      expect(hasAllPermissions(editor, [PERMISSIONS.ADMIN_ACCESS, PERMISSIONS.ADMIN_CONTENT_VIEW])).toBe(true);
    });

    it('should return false if user is missing any permission', () => {
      expect(hasAllPermissions(viewer, [PERMISSIONS.ADMIN_ACCESS, PERMISSIONS.ADMIN_USERS_MANAGE])).toBe(false);
    });
  });

  describe('getRolePermissions', () => {
    it('should return all permissions for super_admin', () => {
      const perms = getRolePermissions('super_admin');
      expect(perms).toContain(PERMISSIONS.ADMIN_SECURITY_MANAGE);
      expect(perms).toContain(PERMISSIONS.ADMIN_USERS_MANAGE);
      expect(perms).toContain(PERMISSIONS.ADMIN_CONTENT_MANAGE);
    });

    it('should return limited permissions for viewer', () => {
      const perms = getRolePermissions('viewer');
      expect(perms).toContain(PERMISSIONS.ADMIN_ACCESS);
      expect(perms).toContain(PERMISSIONS.ADMIN_ANALYTICS_VIEW);
      expect(perms).not.toContain(PERMISSIONS.ADMIN_USERS_MANAGE);
      expect(perms).not.toContain(PERMISSIONS.ADMIN_SECURITY_MANAGE);
    });

    it('should return event permissions for event_manager', () => {
      const perms = getRolePermissions('event_manager');
      expect(perms).toContain(PERMISSIONS.ADMIN_EVENTS_VIEW);
      expect(perms).toContain(PERMISSIONS.ADMIN_EVENTS_MANAGE);
    });

    it('should return moderator permissions', () => {
      const perms = getRolePermissions('moderator');
      expect(perms).toContain(PERMISSIONS.ADMIN_CONTENT_MODERATE);
      expect(perms).toContain(PERMISSIONS.ADMIN_USERS_VIEW);
    });
  });

  describe('canManageRole', () => {
    it('should allow super_admin to manage all roles', () => {
      expect(canManageRole('super_admin', 'admin')).toBe(true);
      expect(canManageRole('super_admin', 'moderator')).toBe(true);
      expect(canManageRole('super_admin', 'viewer')).toBe(true);
    });

    it('should allow admin to manage lower roles but not super_admin', () => {
      expect(canManageRole('admin', 'moderator')).toBe(true);
      expect(canManageRole('admin', 'viewer')).toBe(true);
      expect(canManageRole('admin', 'super_admin')).toBe(false);
      expect(canManageRole('admin', 'admin')).toBe(false);
    });

    it('should not allow viewer to manage any role', () => {
      expect(canManageRole('viewer', 'viewer')).toBe(false);
      expect(canManageRole('viewer', 'member')).toBe(false);
    });
  });
});

describe('Content Visibility', () => {
  describe('canViewContent', () => {
    it('should allow anyone to view public content', () => {
      expect(canViewContent('public', undefined)).toBe(true);
      expect(canViewContent('public', 'viewer')).toBe(true);
    });

    it('should only allow members to view members-only content', () => {
      expect(canViewContent('members', undefined)).toBe(false);
      expect(canViewContent('members', 'viewer')).toBe(false);
      expect(canViewContent('members', 'member')).toBe(true);
      expect(canViewContent('members', 'admin')).toBe(true);
    });

    it('should only allow admins to view admin content', () => {
      expect(canViewContent('admin', 'member')).toBe(false);
      expect(canViewContent('admin', 'moderator')).toBe(true);
      expect(canViewContent('admin', 'admin')).toBe(true);
    });

    it('should only allow owner to view private content', () => {
      expect(canViewContent('private', 'admin', 'author-1', 'user-1')).toBe(false);
      expect(canViewContent('private', 'admin', 'user-1', 'user-1')).toBe(true);
      expect(canViewContent('private', 'super_admin', 'author-1', 'user-1')).toBe(true);
    });
  });

  describe('filterContentByVisibility', () => {
    const testContent = [
      { id: '1', visibility: 'public', authorId: 'author-1' },
      { id: '2', visibility: 'members', authorId: 'author-1' },
      { id: '3', visibility: 'admin', authorId: 'author-1' },
      { id: '4', visibility: 'private', authorId: 'user-1' },
    ];

    it('should filter to only public for anonymous users', () => {
      const filtered = filterContentByVisibility(testContent, undefined);
      expect(filtered).toHaveLength(1);
      expect(filtered[0].id).toBe('1');
    });

    it('should include members content for members', () => {
      const filtered = filterContentByVisibility(testContent, 'member', 'user-1');
      expect(filtered).toHaveLength(3); // public, members, and own private
      expect(filtered.map(c => c.id)).toContain('1');
      expect(filtered.map(c => c.id)).toContain('2');
      expect(filtered.map(c => c.id)).toContain('4');
    });

    it('should include admin content for admins', () => {
      const filtered = filterContentByVisibility(testContent, 'admin', 'user-1');
      expect(filtered).toHaveLength(4); // all content
    });
  });

  describe('getAllowedVisibilityOptions', () => {
    it('should return empty array for viewer', () => {
      const options = getAllowedVisibilityOptions('viewer');
      expect(options).toHaveLength(0);
    });

    it('should include members and private for members (but not public)', () => {
      const options = getAllowedVisibilityOptions('member');
      expect(options).toContain('members');
      expect(options).toContain('private');
      expect(options).not.toContain('public');
    });

    it('should include public, members, private for contributors', () => {
      const options = getAllowedVisibilityOptions('contributor');
      expect(options).toContain('public');
      expect(options).toContain('members');
      expect(options).toContain('private');
      expect(options).not.toContain('admin');
    });

    it('should include admin visibility for admins', () => {
      const options = getAllowedVisibilityOptions('admin');
      expect(options).toContain('admin');
      expect(options).toContain('public');
      expect(options).toContain('members');
      expect(options).toContain('private');
    });
  });
});

describe('Member Role Detection', () => {
  describe('isMemberRole', () => {
    it('should return true only for member role', () => {
      expect(isMemberRole('member')).toBe(true);
    });

    it('should return false for roles other than member', () => {
      expect(isMemberRole('contributor')).toBe(false);
      expect(isMemberRole('editor')).toBe(false);
      expect(isMemberRole('admin')).toBe(false);
    });

    it('should return false for viewer', () => {
      expect(isMemberRole('viewer')).toBe(false);
    });
  });
});
