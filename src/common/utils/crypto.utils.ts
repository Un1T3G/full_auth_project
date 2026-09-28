import * as argon2 from 'argon2';
import * as crypto from 'crypto';

export class CryptoUtils {
  /**
   * Hashes a password using Argon2id with production security parameters
   */
  static async hashPassword(password: string): Promise<string> {
    return argon2.hash(password, {
      type: argon2.argon2id,
      memoryCost: 2 ** 16, // 64 MB
      timeCost: 3,
      parallelism: 1,
    });
  }

  /**
   * Verifies a plain password against an Argon2id hash
   */
  static async verifyPassword(hash: string, plain: string): Promise<boolean> {
    try {
      return await argon2.verify(hash, plain);
    } catch {
      return false;
    }
  }

  /**
   * Generates a cryptographically strong random token
   * @param byteLength Default 32 bytes (64 hex characters)
   */
  static generateRandomToken(byteLength = 32): string {
    return crypto.randomBytes(byteLength).toString('hex');
  }

  /**
   * Hashes a value with SHA-256 (useful for backup codes or token lookups)
   */
  static hashToken(token: string): string {
    return crypto.createHash('sha256').update(token.trim()).digest('hex');
  }

  /**
   * Generates readable backup codes (e.g., "ABCD-1234")
   */
  static generateBackupCodes(count = 10): string[] {
    const codes: string[] = [];
    for (let i = 0; i < count; i++) {
      const part1 = crypto.randomBytes(2).toString('hex').toUpperCase();
      const part2 = crypto.randomBytes(2).toString('hex').toUpperCase();
      codes.push(`${part1}-${part2}`);
    }
    return codes;
  }

  /**
   * Normalizes an email address
   */
  static normalizeEmail(email: string): string {
    return email.trim().toLowerCase();
  }

  /**
   * Password complexity validator:
   * Minimum 8 characters, at least 1 uppercase letter, 1 number, and 1 special character
   */
  static isStrongPassword(password: string): boolean {
    const minLength = password.length >= 8;
    const hasUpper = /[A-Z]/.test(password);
    const hasNumber = /[0-9]/.test(password);
    const hasSpecial = /[^A-Za-z0-9]/.test(password);
    return minLength && hasUpper && hasNumber && hasSpecial;
  }
}
