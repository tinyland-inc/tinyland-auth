









import type { AdminRole } from '../../types/auth.js';





export interface OwnershipUser {
  id: string;
  role?: AdminRole | string;
  handle?: string;
  username?: string;
}





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





export interface OwnershipError {
  code: 'FORBIDDEN';
  message: string;
}




function extractAuthorId(content: OwnedContent): string | null {
  if (content.authorId) return content.authorId;
  if (content.author?.id) return content.author.id;
  if (content.frontmatter?.authorId) return content.frontmatter.authorId;
  if (content.frontmatter?.author?.id) return content.frontmatter.author.id;
  return null;
}




function extractAuthorHandle(content: OwnedContent): string | null {
  if (content.authorHandle) return content.authorHandle;
  if (content.author?.handle) return content.author.handle;
  if (content.frontmatter?.authorHandle) return content.frontmatter.authorHandle;
  if (content.frontmatter?.author?.handle) return content.frontmatter.author.handle;
  return null;
}





export function isContentOwner(user: OwnershipUser, content: OwnedContent): boolean {
  const contentAuthorId = extractAuthorId(content);
  const contentAuthorHandle = extractAuthorHandle(content);

  
  if (contentAuthorId && user.id === contentAuthorId) {
    return true;
  }

  
  const userHandle = user.handle || user.username;
  if (contentAuthorHandle && userHandle === contentAuthorHandle) {
    return true;
  }

  return false;
}






export function canEditContent(user: OwnershipUser, content: OwnedContent): boolean {
  const role = user.role;
  if (!role) return false;

  
  const privilegedRoles = ['super_admin', 'admin', 'editor'];
  if (privilegedRoles.includes(role)) {
    return true;
  }

  
  if (role === 'moderator') {
    return true;
  }

  
  if (role === 'event_manager') {
    return true;
  }

  
  if (['contributor', 'member'].includes(role)) {
    return isContentOwner(user, content);
  }

  return false;
}






export function canDeleteContent(user: OwnershipUser, content: OwnedContent): boolean {
  const role = user.role;
  if (!role) return false;

  
  if (['super_admin', 'admin'].includes(role)) {
    return true;
  }

  
  if (['contributor', 'member'].includes(role)) {
    return isContentOwner(user, content);
  }

  
  if (role === 'event_manager') {
    return isContentOwner(user, content);
  }

  return false;
}





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





export function isSoleOwner(user: OwnershipUser, content: OwnedContent): boolean {
  const role = user.role;

  
  if (role && ['super_admin', 'admin', 'editor', 'moderator'].includes(role)) {
    return false;
  }

  return isContentOwner(user, content);
}
