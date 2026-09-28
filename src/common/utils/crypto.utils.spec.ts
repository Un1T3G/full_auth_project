import { CryptoUtils } from './crypto.utils';

describe('CryptoUtils', () => {
  describe('isStrongPassword', () => {
    it('should accept valid strong passwords', () => {
      expect(CryptoUtils.isStrongPassword('SecureP@ss123')).toBe(true);
      expect(CryptoUtils.isStrongPassword('V3ry$tr0ng!Pass')).toBe(true);
    });

    it('should reject passwords shorter than 8 characters', () => {
      expect(CryptoUtils.isStrongPassword('Sh0rt!')).toBe(false);
    });

    it('should reject passwords without uppercase letter', () => {
      expect(CryptoUtils.isStrongPassword('lowercase123!')).toBe(false);
    });

    it('should reject passwords without digits', () => {
      expect(CryptoUtils.isStrongPassword('NoDigitsHere!')).toBe(false);
    });

    it('should reject passwords without special characters', () => {
      expect(CryptoUtils.isStrongPassword('NoSpecialChar123')).toBe(false);
    });
  });

  describe('normalizeEmail', () => {
    it('should trim and lowercase email', () => {
      expect(CryptoUtils.normalizeEmail('  User.Test@Example.COM  ')).toBe('user.test@example.com');
    });
  });

  describe('generateRandomToken', () => {
    it('should generate token of correct length', () => {
      const token = CryptoUtils.generateRandomToken(32);
      expect(token).toHaveLength(64); // 32 bytes in hex = 64 characters
    });
  });

  describe('generateBackupCodes', () => {
    it('should generate 10 unique backup codes', () => {
      const codes = CryptoUtils.generateBackupCodes(10);
      expect(codes).toHaveLength(10);
      const unique = new Set(codes);
      expect(unique.size).toBe(10);
      codes.forEach((code) => {
        expect(code).toMatch(/^[A-F0-9]{4}-[A-F0-9]{4}$/);
      });
    });
  });

  describe('hashPassword and verifyPassword with Argon2id', () => {
    it('should hash and verify password correctly', async () => {
      const password = 'MySecretPassword123!';
      const hash = await CryptoUtils.hashPassword(password);
      expect(hash).toContain('$argon2id$');

      const isValid = await CryptoUtils.verifyPassword(hash, password);
      expect(isValid).toBe(true);

      const isInvalid = await CryptoUtils.verifyPassword(hash, 'WrongPassword123!');
      expect(isInvalid).toBe(false);
    });
  });
});
