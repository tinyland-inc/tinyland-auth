







import { randomBytes } from 'crypto';
import { authenticator } from 'otplib';
import * as qrcode from 'qrcode';
import type { AdminInvitation, AdminRole, InvitationConfig } from '../../types/index.js';
import type { IStorageAdapter } from '../../storage/interface.js';
import { canManageRole } from '../../core/permissions/index.js';

export interface InvitationServiceConfig {
  
  storage: IStorageAdapter;
  
  config: InvitationConfig;
  
  baseUrl: string;
  
  totpIssuer?: string;
}

export interface CreateInvitationOptions {
  
  role: AdminRole;
  
  createdBy: string;
  
  createdByHandle: string;
  
  expiresInHours?: number;
  
  message?: string;
  
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




export class InvitationService {
  private storage: IStorageAdapter;
  private config: InvitationConfig;
  private baseUrl: string;
  private totpIssuer: string;

  constructor(serviceConfig: InvitationServiceConfig) {
    this.storage = serviceConfig.storage;
    this.config = serviceConfig.config;
    this.baseUrl = serviceConfig.baseUrl;
    this.totpIssuer = serviceConfig.totpIssuer || 'Tinyland.dev';
  }

  


  async createInvitation(options: CreateInvitationOptions): Promise<CreateInvitationResult> {
    try {
      
      const token = randomBytes(32).toString('hex');

      
      const totpSecret = authenticator.generateSecret();

      
      const expiresInHours = options.expiresInHours || this.config.defaultExpiryHours;
      const expiresAt = new Date();
      expiresAt.setHours(expiresAt.getHours() + expiresInHours);

      
      const invitationData: Omit<AdminInvitation, 'id'> = {
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

      
      const invitation = await this.storage.createInvitation(invitationData);

      
      const otpauth = authenticator.keyuri(
        `invite-${invitation.id}`,
        `${this.totpIssuer} (Invite)`,
        totpSecret
      );
      const qrCode = await qrcode.toDataURL(otpauth);

      
      const inviteUrl = `${this.baseUrl}/admin/accept-invite?token=${token}`;

      return {
        success: true,
        invitation,
        inviteUrl,
        totpSecret,
        qrCode,
      };
    } catch (error) {
      console.error('[InvitationService] Create error:', error);
      return {
        success: false,
        error: 'Failed to create invitation',
      };
    }
  }

  


  async getInvitation(token: string): Promise<AdminInvitation | null> {
    const invitation = await this.storage.getInvitation(token);

    if (!invitation) return null;

    
    if (new Date(invitation.expiresAt) < new Date()) {
      return null;
    }

    
    if (invitation.usedAt) {
      return null;
    }

    return invitation;
  }

  


  async markAsUsed(token: string, usedBy: string): Promise<boolean> {
    try {
      await this.storage.updateInvitation(token, {
        usedAt: new Date().toISOString(),
        usedBy,
        isActive: false,
      });
      return true;
    } catch {
      return false;
    }
  }

  


  async revokeInvitation(token: string): Promise<boolean> {
    return this.storage.deleteInvitation(token);
  }

  


  async listPendingInvitations(): Promise<AdminInvitation[]> {
    return this.storage.getPendingInvitations();
  }

  


  async getStatistics(): Promise<{
    total: number;
    pending: number;
    expired: number;
    used: number;
  }> {
    const all = await this.storage.getAllInvitations();
    const now = new Date();

    return {
      total: all.length,
      pending: all.filter(i => new Date(i.expiresAt) > now && !i.usedAt).length,
      expired: all.filter(i => new Date(i.expiresAt) <= now && !i.usedAt).length,
      used: all.filter(i => i.usedAt).length,
    };
  }

  


  async cleanupExpired(): Promise<number> {
    return this.storage.cleanupExpiredInvitations();
  }

  


  async extendInvitation(token: string, additionalHours: number): Promise<boolean> {
    const invitation = await this.storage.getInvitation(token);
    if (!invitation || invitation.usedAt) return false;

    const newExpiry = new Date(invitation.expiresAt);
    newExpiry.setHours(newExpiry.getHours() + additionalHours);

    try {
      await this.storage.updateInvitation(token, {
        expiresAt: newExpiry.toISOString(),
      });
      return true;
    } catch {
      return false;
    }
  }

  


  canInviteForRole(creatorRole: AdminRole, targetRole: AdminRole): boolean {
    return canManageRole(creatorRole, targetRole);
  }
}




export function createInvitationService(config: InvitationServiceConfig): InvitationService {
  return new InvitationService(config);
}
