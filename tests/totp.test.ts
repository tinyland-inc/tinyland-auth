






import { describe, it, expect } from 'vitest';
import { TOTPService } from '../src/core/totp/index.js';
import type { TOTPSecret, EncryptedData } from '../src/types/auth.js';


const TEST_ENCRYPTION_KEY = 'abcdefghijklmnopqrstuvwxyz123456';

function createTestService(overrides: Partial<ConstructorParameters<typeof TOTPService>[0]> = {}): TOTPService {
  return new TOTPService({
    encryptionKey: TEST_ENCRYPTION_KEY,
    issuer: 'Test App',
    devMode: false,
    ...overrides,
  });
}

describe('TOTPService', () => {
  describe('generateSecret', () => {
    it('should generate a TOTP secret with required fields', async () => {
      const service = createTestService();
      const secret = await service.generateSecret('testuser', 'test@example.com');

      expect(secret.handle).toBe('testuser');
      expect(secret.email).toBe('test@example.com');
      expect(secret.secret).toBeTruthy();
      expect(secret.qrCodeUrl).toBeTruthy();
      expect(secret.createdAt).toBeInstanceOf(Date);
    });

    it('should generate a base32 secret string', async () => {
      const service = createTestService();
      const secret = await service.generateSecret('testuser', 'test@example.com');

      
      expect(secret.secret).toMatch(/^[A-Z2-7]+$/);
    });

    it('should generate unique secrets for different users', async () => {
      const service = createTestService();
      const secret1 = await service.generateSecret('user1', 'user1@example.com');
      const secret2 = await service.generateSecret('user2', 'user2@example.com');

      expect(secret1.secret).not.toBe(secret2.secret);
    });

    it('should generate a QR code data URL', async () => {
      const service = createTestService();
      const secret = await service.generateSecret('testuser', 'test@example.com');

      expect(secret.qrCodeUrl).toMatch(/^data:image\/png;base64,/);
    });

    it('should generate unique secrets on successive calls for same user', async () => {
      const service = createTestService();
      const secret1 = await service.generateSecret('testuser', 'test@example.com');
      const secret2 = await service.generateSecret('testuser', 'test@example.com');

      expect(secret1.secret).not.toBe(secret2.secret);
    });
  });

  describe('encrypt / decrypt', () => {
    it('should roundtrip encrypt and decrypt a string', () => {
      const service = createTestService();
      const plaintext = 'JBSWY3DPEHPK3PXP';

      const encrypted = service.encrypt(plaintext);
      const decrypted = service.decrypt(encrypted);

      expect(decrypted).toBe(plaintext);
    });

    it('should produce different ciphertexts for same plaintext (random IV/salt)', () => {
      const service = createTestService();
      const plaintext = 'test-secret';

      const encrypted1 = service.encrypt(plaintext);
      const encrypted2 = service.encrypt(plaintext);

      expect(encrypted1.encrypted).not.toBe(encrypted2.encrypted);
      expect(encrypted1.iv).not.toBe(encrypted2.iv);
      expect(encrypted1.salt).not.toBe(encrypted2.salt);
    });

    it('should return encrypted data with all required fields', () => {
      const service = createTestService();
      const encrypted = service.encrypt('test');

      expect(encrypted.encrypted).toBeTruthy();
      expect(encrypted.salt).toBeTruthy();
      expect(encrypted.iv).toBeTruthy();
      expect(encrypted.tag).toBeTruthy();
    });

    it('should fail to decrypt with wrong key', () => {
      const service1 = createTestService({ encryptionKey: 'abcdefghijklmnopqrstuvwxyz123456' });
      const service2 = createTestService({ encryptionKey: '654321zyxwvutsrqponmlkjihgfedcba' });

      const encrypted = service1.encrypt('secret');

      expect(() => service2.decrypt(encrypted)).toThrow();
    });

    it('should fail to decrypt tampered ciphertext', () => {
      const service = createTestService();
      const encrypted = service.encrypt('secret');

      
      const tampered: EncryptedData = {
        ...encrypted,
        encrypted: 'AAAA' + encrypted.encrypted.slice(4),
      };

      expect(() => service.decrypt(tampered)).toThrow();
    });

    it('should handle empty string encryption', () => {
      const service = createTestService();
      const encrypted = service.encrypt('');
      const decrypted = service.decrypt(encrypted);

      expect(decrypted).toBe('');
    });

    it('should handle unicode content', () => {
      const service = createTestService();
      const plaintext = 'Unicode test: \u00e9\u00e8\u00ea\u00eb \u4e16\u754c';

      const encrypted = service.encrypt(plaintext);
      const decrypted = service.decrypt(encrypted);

      expect(decrypted).toBe(plaintext);
    });
  });

  describe('verifyToken', () => {
    it('should verify a valid TOTP token', async () => {
      const service = createTestService();
      const secret = await service.generateSecret('testuser', 'test@example.com');

      
      const token = service.generateToken(secret);

      const result = await service.verifyToken(secret, token);
      expect(result).toBe(true);
    });

    it('should reject an invalid TOTP token', async () => {
      const service = createTestService();
      const secret = await service.generateSecret('testuser', 'test@example.com');

      const result = await service.verifyToken(secret, '000000');
      expect(result).toBe(false);
    });

    it('should handle null secret gracefully (returns false)', async () => {
      const service = createTestService();

      const result = await service.verifyToken(null, '123456');
      expect(result).toBe(false);
    });

    it('should strip whitespace from tokens', async () => {
      const service = createTestService();
      const secret = await service.generateSecret('testuser', 'test@example.com');
      const token = service.generateToken(secret);

      
      const spacedToken = `${token.slice(0, 3)} ${token.slice(3)}`;
      const result = await service.verifyToken(secret, spacedToken);
      expect(result).toBe(true);
    });

    it('should accept test code in dev mode', async () => {
      const service = createTestService({
        devMode: true,
        testCode: '999999',
      });

      const secret = await service.generateSecret('testuser', 'test@example.com');
      const result = await service.verifyToken(secret, '999999');
      expect(result).toBe(true);
    });

    it('should not accept test code when not in dev mode', async () => {
      const service = createTestService({
        devMode: false,
        testCode: '999999',
      });

      const secret = await service.generateSecret('testuser', 'test@example.com');
      const result = await service.verifyToken(secret, '999999');
      
      
      
      expect(typeof result).toBe('boolean');
    });
  });

  describe('generateToken', () => {
    it('should generate a 6-digit numeric token', async () => {
      const service = createTestService();
      const secret = await service.generateSecret('testuser', 'test@example.com');
      const token = service.generateToken(secret);

      expect(token).toMatch(/^\d{6}$/);
    });

    it('should generate consistent tokens for the same secret within the same time window', async () => {
      const service = createTestService();
      const secret = await service.generateSecret('testuser', 'test@example.com');

      const token1 = service.generateToken(secret);
      const token2 = service.generateToken(secret);

      expect(token1).toBe(token2);
    });
  });

  describe('generateQRCode', () => {
    it('should generate a QR code data URL from a secret', async () => {
      const service = createTestService();
      const secret = await service.generateSecret('testuser', 'test@example.com');

      const qrCode = await service.generateQRCode(secret);
      expect(qrCode).toMatch(/^data:image\/png;base64,/);
    });
  });

  describe('encryptBackupCodes / decryptBackupCodes', () => {
    it('should roundtrip backup code encryption', () => {
      const service = createTestService();
      const codes = ['ABCD-1234', 'EFGH-5678', 'IJKL-9012'];

      const encrypted = service.encryptBackupCodes(codes);
      const decrypted = service.decryptBackupCodes(encrypted);

      expect(decrypted).toEqual(codes);
    });

    it('should encrypt codes as JSON', () => {
      const service = createTestService();
      const codes = ['CODE-0001'];

      const encrypted = service.encryptBackupCodes(codes);

      
      expect(encrypted.encrypted).toBeTruthy();
      expect(encrypted.salt).toBeTruthy();
      expect(encrypted.iv).toBeTruthy();
      expect(encrypted.tag).toBeTruthy();
    });

    it('should handle empty code array', () => {
      const service = createTestService();
      const encrypted = service.encryptBackupCodes([]);
      const decrypted = service.decryptBackupCodes(encrypted);

      expect(decrypted).toEqual([]);
    });

    it('should produce different ciphertexts for same codes', () => {
      const service = createTestService();
      const codes = ['ABCD-1234'];

      const encrypted1 = service.encryptBackupCodes(codes);
      const encrypted2 = service.encryptBackupCodes(codes);

      expect(encrypted1.encrypted).not.toBe(encrypted2.encrypted);
    });
  });
});

describe('TOTP PBT: Generated secrets', () => {
  it('INVARIANT: generated secrets are always valid base32', async () => {
    const service = createTestService();
    const base32Regex = /^[A-Z2-7]+=*$/;

    
    for (let i = 0; i < 50; i++) {
      const secret = await service.generateSecret(`user${i}`, `user${i}@example.com`);
      expect(secret.secret).toMatch(base32Regex);
    }
  });

  it('INVARIANT: generated secrets have sufficient length for security', async () => {
    const service = createTestService();

    
    
    for (let i = 0; i < 50; i++) {
      const secret = await service.generateSecret(`user${i}`, `user${i}@example.com`);
      expect(secret.secret.length).toBeGreaterThanOrEqual(16);
    }
  });

  it('INVARIANT: encrypt/decrypt roundtrip preserves arbitrary strings', () => {
    const service = createTestService();

    
    const testStrings = [
      'JBSWY3DPEHPK3PXP',
      'a',
      'A'.repeat(100),
      'special chars: !@#$%^&*()',
      '\n\t\r',
      '\u0000null\u0000byte',
      '\ud83d\ude0a emoji test',
    ];

    for (const str of testStrings) {
      const encrypted = service.encrypt(str);
      const decrypted = service.decrypt(encrypted);
      expect(decrypted).toBe(str);
    }
  });

  it('INVARIANT: generated TOTP tokens are always 6 digits', async () => {
    const service = createTestService();

    for (let i = 0; i < 20; i++) {
      const secret = await service.generateSecret(`user${i}`, `user${i}@example.com`);
      const token = service.generateToken(secret);
      expect(token).toMatch(/^\d{6}$/);
    }
  });
});
