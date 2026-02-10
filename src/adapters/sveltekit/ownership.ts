/**
 * SvelteKit Ownership Guards
 *
 * Wraps the core ownership functions with SvelteKit error() responses.
 *
 * @module @tinyland/auth/sveltekit
 */

import { error } from '@sveltejs/kit';
import {
  canEditContent,
  canDeleteContent,
  isContentOwner,
  isSoleOwner,
  type OwnershipUser,
  type OwnedContent,
} from '../../core/permissions/ownership.js';

// Re-export pure functions as-is (no SvelteKit dependency needed)
export { isContentOwner, isSoleOwner };
export { canEditContent as canEditOwnedContent, canDeleteContent as canDeleteOwnedContent };
export type { OwnershipUser, OwnedContent };

/**
 * Guard that throws SvelteKit 403 error if user cannot edit content.
 * Use this in +page.server.ts load functions.
 */
export function requireContentEditPermission(
  user: OwnershipUser,
  content: OwnedContent
): void {
  if (!canEditContent(user, content)) {
    throw error(403, {
      message: 'You do not have permission to edit this content',
    });
  }
}

/**
 * Guard that throws SvelteKit 403 error if user cannot delete content.
 * Use this in +page.server.ts action functions.
 */
export function requireContentDeletePermission(
  user: OwnershipUser,
  content: OwnedContent
): void {
  if (!canDeleteContent(user, content)) {
    throw error(403, {
      message: 'You do not have permission to delete this content',
    });
  }
}
