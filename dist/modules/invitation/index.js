/**
 * Invitation Service Module
 *
 * Manages admin user invitations with token-based flow.
 *
 * @module @tinyland/auth/modules/invitation
 */
import { randomBytes } from 'crypto';
import { authenticator } from 'otplib';
import * as qrcode from 'qrcode';
import { canManageRole } from '../../core/permissions/index.js';
/**
 * Invitation Service
 */
export class InvitationService {
    storage;
    config;
    baseUrl;
    totpIssuer;
    constructor(serviceConfig) {
        this.storage = serviceConfig.storage;
        this.config = serviceConfig.config;
        this.baseUrl = serviceConfig.baseUrl;
        this.totpIssuer = serviceConfig.totpIssuer || 'Tinyland.dev';
    }
    /**
     * Create a new invitation
     */
    async createInvitation(options) {
        try {
            // Generate secure token
            const token = randomBytes(32).toString('hex');
            // Generate temporary TOTP secret
            const totpSecret = authenticator.generateSecret();
            // Calculate expiration
            const expiresInHours = options.expiresInHours || this.config.defaultExpiryHours;
            const expiresAt = new Date();
            expiresAt.setHours(expiresAt.getHours() + expiresInHours);
            // Create invitation object
            const invitationData = {
                token,
                email: options.email || '',
                role: options.role,
                createdBy: options.createdBy,
                createdAt: new Date().toISOString(),
                expiresAt: expiresAt.toISOString(),
                temporaryTotpSecret: totpSecret,
                isActive: true,
                metadata: {
                    inviterHandle: options.createdByHandle,
                    message: options.message,
                },
            };
            // Save to storage
            const invitation = await this.storage.createInvitation(invitationData);
            // Generate QR code
            const otpauth = authenticator.keyuri(`invite-${invitation.id}`, `${this.totpIssuer} (Invite)`, totpSecret);
            const qrCode = await qrcode.toDataURL(otpauth);
            // Build invitation URL
            const inviteUrl = `${this.baseUrl}/admin/accept-invite?token=${token}`;
            return {
                success: true,
                invitation,
                inviteUrl,
                totpSecret,
                qrCode,
            };
        }
        catch (error) {
            console.error('[InvitationService] Create error:', error);
            return {
                success: false,
                error: 'Failed to create invitation',
            };
        }
    }
    /**
     * Get invitation by token
     */
    async getInvitation(token) {
        const invitation = await this.storage.getInvitation(token);
        if (!invitation)
            return null;
        // Check expiration
        if (new Date(invitation.expiresAt) < new Date()) {
            return null;
        }
        // Check if already used
        if (invitation.usedAt) {
            return null;
        }
        return invitation;
    }
    /**
     * Mark invitation as used
     */
    async markAsUsed(token, usedBy) {
        try {
            await this.storage.updateInvitation(token, {
                usedAt: new Date().toISOString(),
                usedBy,
                isActive: false,
            });
            return true;
        }
        catch {
            return false;
        }
    }
    /**
     * Revoke an invitation
     */
    async revokeInvitation(token) {
        return this.storage.deleteInvitation(token);
    }
    /**
     * List pending invitations
     */
    async listPendingInvitations() {
        return this.storage.getPendingInvitations();
    }
    /**
     * Get invitation statistics
     */
    async getStatistics() {
        const all = await this.storage.getAllInvitations();
        const now = new Date();
        return {
            total: all.length,
            pending: all.filter(i => new Date(i.expiresAt) > now && !i.usedAt).length,
            expired: all.filter(i => new Date(i.expiresAt) <= now && !i.usedAt).length,
            used: all.filter(i => i.usedAt).length,
        };
    }
    /**
     * Clean up expired invitations
     */
    async cleanupExpired() {
        return this.storage.cleanupExpiredInvitations();
    }
    /**
     * Extend invitation expiry
     */
    async extendInvitation(token, additionalHours) {
        const invitation = await this.storage.getInvitation(token);
        if (!invitation || invitation.usedAt)
            return false;
        const newExpiry = new Date(invitation.expiresAt);
        newExpiry.setHours(newExpiry.getHours() + additionalHours);
        try {
            await this.storage.updateInvitation(token, {
                expiresAt: newExpiry.toISOString(),
            });
            return true;
        }
        catch {
            return false;
        }
    }
    /**
     * Validate if creator can invite for target role
     */
    canInviteForRole(creatorRole, targetRole) {
        return canManageRole(creatorRole, targetRole);
    }
}
/**
 * Create invitation service instance
 */
export function createInvitationService(config) {
    return new InvitationService(config);
}
//# sourceMappingURL=index.js.map