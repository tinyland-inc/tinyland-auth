



import { describe, it, expect, beforeEach } from 'vitest';
import { BootstrapService, createBootstrapService } from '../src/modules/bootstrap/index.js';
import { MemoryStorageAdapter } from '../src/storage/memory.js';
import type { BootstrapServiceConfig, BootstrapState } from '../src/modules/bootstrap/index.js';
import type { EncryptedTOTPSecret } from '../src/types/auth.js';


const mockGenerateTOTPSecret = () => 'MOCK_SECRET_BASE32';
const mockGenerateQRCode = async () => 'data:image/png;base64,mockqrcode';
const mockVerifyTOTP = (secret: string, token: string) => token === '123456';
const mockEncryptTOTPSecret = async (handle: string, secret: string): Promise<EncryptedTOTPSecret> => ({
  userId: 'pending',
  handle,
  encryptedSecret: `encrypted:${secret}`,
  iv: 'mock-iv',
  authTag: 'mock-tag',
  salt: 'mock-salt',
  createdAt: new Date().toISOString(),
  backupCodesGenerated: false,
  version: 1,
});

describe('BootstrapService', () => {
  let storage: MemoryStorageAdapter;
  let config: BootstrapServiceConfig;
  let service: BootstrapService;

  beforeEach(async () => {
    storage = new MemoryStorageAdapter();
    await storage.init();

    config = {
      storage,
      appName: 'Test App',
      bcryptRounds: 4, 
      backupCodesCount: 5,
      generateTOTPSecret: mockGenerateTOTPSecret,
      generateQRCode: mockGenerateQRCode,
      verifyTOTP: mockVerifyTOTP,
      encryptTOTPSecret: mockEncryptTOTPSecret,
    };

    service = new BootstrapService(config);
  });

  describe('getStatus', () => {
    it('should indicate bootstrap needed when no users exist', async () => {
      const status = await service.getStatus();

      expect(status.needsBootstrap).toBe(true);
      expect(status.hasUsers).toBe(false);
      expect(status.systemConfigured).toBe(false);
    });

    it('should indicate bootstrap not needed when users exist', async () => {
      await storage.createUser({
        handle: 'existing',
        email: 'existing@test.com',
        passwordHash: 'hash',
        role: 'admin',
        isActive: true,
        totpEnabled: false,
        needsOnboarding: false,
        onboardingStep: 0,
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
      });

      const status = await service.getStatus();

      expect(status.needsBootstrap).toBe(false);
      expect(status.hasUsers).toBe(true);
      expect(status.systemConfigured).toBe(true);
    });
  });

  describe('initiate', () => {
    it('should create bootstrap state with valid request', async () => {
      const result = await service.initiate({
        handle: 'admin',
        password: 'SecurePassword123!',
        displayName: 'Admin User',
        email: 'admin@test.com',
      });

      expect(result.state).toBeDefined();
      expect(result.state.handle).toBe('admin');
      expect(result.state.displayName).toBe('Admin User');
      expect(result.state.email).toBe('admin@test.com');
      expect(result.state.totpSecret).toBe('MOCK_SECRET_BASE32');
      expect(result.state.backupCodes).toHaveLength(5);
      expect(result.qrCodeUrl).toBe('data:image/png;base64,mockqrcode');
      expect(result.backupCodes).toEqual(result.state.backupCodes);
    });

    it('should hash the password', async () => {
      const result = await service.initiate({
        handle: 'admin',
        password: 'TestPassword123!',
        displayName: 'Admin',
      });

      expect(result.state.passwordHash).toBeDefined();
      expect(result.state.passwordHash).toMatch(/^\$2[aby]?\$/);
      expect(result.state.passwordHash).not.toBe('TestPassword123!');
    });

    it('should reject invalid handle format', async () => {
      await expect(
        service.initiate({
          handle: '123invalid', 
          password: 'test',
          displayName: 'Test',
        })
      ).rejects.toThrow('Handle must start with a letter');

      await expect(
        service.initiate({
          handle: 'ab', 
          password: 'test',
          displayName: 'Test',
        })
      ).rejects.toThrow('Handle must start with a letter');
    });

    it('should reject if users already exist', async () => {
      await storage.createUser({
        handle: 'existing',
        email: 'existing@test.com',
        passwordHash: 'hash',
        role: 'admin',
        isActive: true,
        totpEnabled: false,
        needsOnboarding: false,
        onboardingStep: 0,
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
      });

      await expect(
        service.initiate({
          handle: 'newadmin',
          password: 'test',
          displayName: 'Test',
        })
      ).rejects.toThrow('Bootstrap not allowed');
    });
  });

  describe('updateProfile', () => {
    it('should add profile data to state', async () => {
      const { state } = await service.initiate({
        handle: 'admin',
        password: 'test',
        displayName: 'Admin',
      });

      const updated = service.updateProfile(state, {
        bio: 'System administrator',
        pronouns: 'they/them',
      });

      expect(updated.profile).toBeDefined();
      expect(updated.profile?.bio).toBe('System administrator');
      expect(updated.profile?.pronouns).toBe('they/them');
      expect(updated.step).toBe(2);
    });
  });

  describe('complete', () => {
    let validState: BootstrapState;

    beforeEach(async () => {
      const result = await service.initiate({
        handle: 'admin',
        password: 'SecurePassword123!',
        displayName: 'Admin User',
        email: 'admin@test.com',
      });
      validState = result.state;
    });

    it('should complete bootstrap with valid TOTP', async () => {
      const result = await service.complete(validState, {
        handle: 'admin',
        totpCode: '123456', 
      });

      expect(result.success).toBe(true);
      expect(result.user).toBeDefined();
      expect(result.user?.handle).toBe('admin');
      expect(result.user?.role).toBe('super_admin');
      expect(result.backupCodes).toHaveLength(5);

      
      const user = await storage.getUserByHandle('admin');
      expect(user).not.toBeNull();
      expect(user?.role).toBe('super_admin');
      expect(user?.totpEnabled).toBe(true);
    });

    it('should reject invalid TOTP code', async () => {
      const result = await service.complete(validState, {
        handle: 'admin',
        totpCode: '000000', 
      });

      expect(result.success).toBe(false);
      expect(result.error).toContain('Invalid TOTP code');

      
      const user = await storage.getUserByHandle('admin');
      expect(user).toBeNull();
    });

    it('should reject mismatched handle', async () => {
      const result = await service.complete(validState, {
        handle: 'different',
        totpCode: '123456',
      });

      expect(result.success).toBe(false);
      expect(result.error).toBe('Handle mismatch');
    });

    it('should reject expired state', async () => {
      const expiredState: BootstrapState = {
        ...validState,
        timestamp: Date.now() - 15 * 60 * 1000, 
      };

      const result = await service.complete(expiredState, {
        handle: 'admin',
        totpCode: '123456',
      });

      expect(result.success).toBe(false);
      expect(result.error).toContain('expired');
    });

    it('should save TOTP secret and backup codes', async () => {
      await service.complete(validState, {
        handle: 'admin',
        totpCode: '123456',
      });

      const secret = await storage.getTOTPSecret('admin');
      expect(secret).not.toBeNull();
      expect(secret?.handle).toBe('admin');

      const user = await storage.getUserByHandle('admin');
      const backupCodes = await storage.getBackupCodes(user!.id);
      expect(backupCodes).not.toBeNull();
      expect(backupCodes?.codes).toHaveLength(5);
    });

    it('should log audit event', async () => {
      await service.complete(validState, {
        handle: 'admin',
        totpCode: '123456',
      });

      const events = await storage.getRecentAuditEvents(10);
      const bootstrapEvent = events.find(e => e.type === 'BOOTSTRAP_COMPLETED');
      expect(bootstrapEvent).toBeDefined();
      expect(bootstrapEvent?.handle).toBe('admin');
    });
  });

  describe('isStateValid', () => {
    it('should return true for fresh state', async () => {
      const { state } = await service.initiate({
        handle: 'admin',
        password: 'test',
        displayName: 'Admin',
      });

      expect(service.isStateValid(state)).toBe(true);
    });

    it('should return false for expired state', async () => {
      const { state } = await service.initiate({
        handle: 'admin',
        password: 'test',
        displayName: 'Admin',
      });

      const expiredState: BootstrapState = {
        ...state,
        timestamp: Date.now() - 15 * 60 * 1000, 
      };

      expect(service.isStateValid(expiredState, 600000)).toBe(false); 
    });

    it('should return false for invalid state', () => {
      expect(service.isStateValid(null as any)).toBe(false);
      expect(service.isStateValid({} as any)).toBe(false);
    });
  });

  describe('createBootstrapService', () => {
    it('should create service instance', () => {
      const svc = createBootstrapService(config);
      expect(svc).toBeInstanceOf(BootstrapService);
    });
  });
});
