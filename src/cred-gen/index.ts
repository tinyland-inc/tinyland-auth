/**
 * Credentials Sub-entry Point
 *
 * Credential generation, card creation, and helper utilities.
 * Framework-agnostic: does not depend on $lib or framework-specific APIs.
 *
 * NOTE: The image-based credential card generator (generateCredentialsCard)
 * from the original credentialsGenerator.ts requires the `sharp` dependency
 * and is NOT included in this package to avoid the heavy native dependency.
 * Only the text-based card generator and helper utilities are provided.
 *
 * @module @tinyland-inc/tinyland-auth/credentials
 */

export {
  generateTextCredentialsCard,
  maskPassword,
  escapeXml,
  type CredentialsCardData,
  type CardDesignOptions,
} from './generator.js';

export {
  generateUserCredentials,
  generateCredentialsEmailHtml,
  generateSecureCredentialsLink,
  createCredentialsDownloadResponse,
  type UserCredentials,
} from './helpers.js';
