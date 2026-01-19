/**
 * Invitation Service Module
 *
 * Manages admin user invitations with token-based flow.
 *
 * @module @tinyland/auth/modules/invitation
 */
import type { AdminInvitation, AdminRole, InvitationConfig } from '../../types/index.js';
import type { IStorageAdapter } from '../../storage/interface.js';
export interface InvitationServiceConfig {
    /** Storage adapter */
    storage: IStorageAdapter;
    /** Invitation configuration */
    config: InvitationConfig;
    /** Base URL for invitation links */
    baseUrl: string;
    /** TOTP issuer name */
    totpIssuer?: string;
}
export interface CreateInvitationOptions {
    /** Role for the invited user */
    role: AdminRole;
    /** ID of the user creating the invitation */
    createdBy: string;
    /** Handle of the user creating the invitation */
    createdByHandle: string;
    /** Custom expiry in hours */
    expiresInHours?: number;
    /** Optional message for the invitee */
    message?: string;
    /** Optional email for reference */
    email?: string;
}
export interface CreateInvitationResult {
    success: boolean;
    invitation?: AdminInvitation;
    inviteUrl?: string;
    totpSecret?: string;
    qrCode?: string;
    error?: string;
}
/**
 * Invitation Service
 */
export declare class InvitationService {
    private storage;
    private config;
    private baseUrl;
    private totpIssuer;
    constructor(serviceConfig: InvitationServiceConfig);
    /**
     * Create a new invitation
     */
    createInvitation(options: CreateInvitationOptions): Promise<CreateInvitationResult>;
    /**
     * Get invitation by token
     */
    getInvitation(token: string): Promise<AdminInvitation | null>;
    /**
     * Mark invitation as used
     */
    markAsUsed(token: string, usedBy: string): Promise<boolean>;
    /**
     * Revoke an invitation
     */
    revokeInvitation(token: string): Promise<boolean>;
    /**
     * List pending invitations
     */
    listPendingInvitations(): Promise<AdminInvitation[]>;
    /**
     * Get invitation statistics
     */
    getStatistics(): Promise<{
        total: number;
        pending: number;
        expired: number;
        used: number;
    }>;
    /**
     * Clean up expired invitations
     */
    cleanupExpired(): Promise<number>;
    /**
     * Extend invitation expiry
     */
    extendInvitation(token: string, additionalHours: number): Promise<boolean>;
    /**
     * Validate if creator can invite for target role
     */
    canInviteForRole(creatorRole: AdminRole, targetRole: AdminRole): boolean;
}
/**
 * Create invitation service instance
 */
export declare function createInvitationService(config: InvitationServiceConfig): InvitationService;
//# sourceMappingURL=index.d.ts.map