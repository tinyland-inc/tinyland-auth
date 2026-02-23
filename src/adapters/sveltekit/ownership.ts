







import { error } from '@sveltejs/kit';
import {
  canEditContent,
  canDeleteContent,
  isContentOwner,
  isSoleOwner,
  type OwnershipUser,
  type OwnedContent,
} from '../../core/permissions/ownership.js';


export { isContentOwner, isSoleOwner };
export { canEditContent as canEditOwnedContent, canDeleteContent as canDeleteOwnedContent };
export type { OwnershipUser, OwnedContent };





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
