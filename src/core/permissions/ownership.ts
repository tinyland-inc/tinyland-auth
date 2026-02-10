/**
 * Content Ownership Verification Utilities
 *
 * Determines if a user owns content and can perform edit/delete operations.
 * Framework-agnostic: throws plain error objects instead of SvelteKit error().
 * The SvelteKit adapter wraps these with proper HTTP error responses.
 *
 * @module @tinyland/auth/core/permissions/ownership
 */

import type { AdminRole } from '../../types/auth.js';

/**
 * Minimal user interface for ownership checks.
 * Works with both full AdminUser and session user from adminGuard.
 */
export interface OwnershipUser {
  id: string;
  role?: AdminRole | string;
  handle?: string;
  username?: string;
}

/**
 * Interface for content items with ownership information.
 * Supports multiple formats for flexible content structures.
 */
export interface OwnedContent {
  authorId?: string | null;
  authorHandle?: string | null;
  author?: {
    id?: string;
    handle?: string;
  };
  frontmatter?: {
    authorId?: string;
    authorHandle?: string;
    author?: {
      id?: string;
      handle?: string;
    };
  };
}

/**
 * Error thrown when ownership permission checks fail.
 * The SvelteKit adapter converts this to an HTTP 403 response.
 */
export interface OwnershipError {
  code: 'FORBIDDEN';
  message: string;
}

/**
 * Extract author ID from content (handles various formats)
 */
function extractAuthorId(content: OwnedContent): string | null {
  if (content.authorId) return content.authorId;
  if (content.author?.id) return content.author.id;
  if (content.frontmatter?.authorId) return content.frontmatter.authorId;
  if (content.frontmatter?.author?.id) return content.frontmatter.author.id;
  return null;
}

/**
 * Extract author handle from content (handles various formats)
 */
function extractAuthorHandle(content: OwnedContent): string | null {
  if (content.authorHandle) return content.authorHandle;
  if (content.author?.handle) return content.author.handle;
  if (content.frontmatter?.authorHandle) return content.frontmatter.authorHandle;
  if (content.frontmatter?.author?.handle) return content.frontmatter.author.handle;
  return null;
}

/**
 * Check if user owns the content.
 * Compares both authorId and authorHandle for robustness.
 */
export function isContentOwner(user: OwnershipUser, content: OwnedContent): boolean {
  const contentAuthorId = extractAuthorId(content);
  const contentAuthorHandle = extractAuthorHandle(content);

  // Check by ID (most reliable)
  if (contentAuthorId && user.id === contentAuthorId) {
    return true;
  }

  // Check by handle (fallback)
  const userHandle = user.handle || user.username;
  if (contentAuthorHandle && userHandle === contentAuthorHandle) {
    return true;
  }

  return false;
}

/**
 * Check if user can edit the content.
 * - Owners can always edit their own content
 * - Editors and above can edit any content
 */
export function canEditContent(user: OwnershipUser, content: OwnedContent): boolean {
  const role = user.role;
  if (!role) return false;

  // Super admin, admin, editor can edit anything
  const privilegedRoles = ['super_admin', 'admin', 'editor'];
  if (privilegedRoles.includes(role)) {
    return true;
  }

  // Moderators can edit for content moderation
  if (role === 'moderator') {
    return true;
  }

  // Event managers can edit events
  if (role === 'event_manager') {
    return true;
  }

  // Contributors and members can edit their own content
  if (['contributor', 'member'].includes(role)) {
    return isContentOwner(user, content);
  }

  return false;
}

/**
 * Check if user can delete the content.
 * - Owners can delete their own content
 * - Admins can delete any content
 */
export function canDeleteContent(user: OwnershipUser, content: OwnedContent): boolean {
  const role = user.role;
  if (!role) return false;

  // Super admin and admin can delete anything
  if (['super_admin', 'admin'].includes(role)) {
    return true;
  }

  // For members/contributors: can delete their own content
  if (['contributor', 'member'].includes(role)) {
    return isContentOwner(user, content);
  }

  // Event managers can delete events they own
  if (role === 'event_manager') {
    return isContentOwner(user, content);
  }

  return false;
}

/**
 * Guard that throws if user cannot edit content.
 * Throws a plain OwnershipError (not SvelteKit error).
 */
export function requireContentEditPermission(
  user: OwnershipUser,
  content: OwnedContent
): void {
  if (!canEditContent(user, content)) {
    throw {
      code: 'FORBIDDEN',
      message: 'You do not have permission to edit this content',
    } satisfies OwnershipError;
  }
}

/**
 * Guard that throws if user cannot delete content.
 * Throws a plain OwnershipError (not SvelteKit error).
 */
export function requireContentDeletePermission(
  user: OwnershipUser,
  content: OwnedContent
): void {
  if (!canDeleteContent(user, content)) {
    throw {
      code: 'FORBIDDEN',
      message: 'You do not have permission to delete this content',
    } satisfies OwnershipError;
  }
}

/**
 * Check if user is the owner and no one else can access.
 * Useful for determining if edit warnings should be shown.
 */
export function isSoleOwner(user: OwnershipUser, content: OwnedContent): boolean {
  const role = user.role;

  // Admins/editors are never "sole" owners - they have override access
  if (role && ['super_admin', 'admin', 'editor', 'moderator'].includes(role)) {
    return false;
  }

  return isContentOwner(user, content);
}
