import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Request, Response } from 'express';
import { generateSecret, generateURI, verifySync } from 'otplib';
import * as QRCode from 'qrcode';
import { PrismaService } from '../../prisma/prisma.service';
import { SessionService } from '../session/session.service';
import { AuthService } from '../auth/auth.service';
import { CryptoUtils } from '../../common/utils/crypto.utils';
import { MfaSetupPayload } from './dto/mfa-setup.payload';
import { AuthPayload } from '../auth/dto/auth.payload';
import {
  AuthErrorCode,
  CustomAuthError,
  InvalidTokenError,
} from '../../common/errors/auth.errors';
import { User } from '@prisma/client';

@Injectable()
export class MfaService {
  private readonly logger = new Logger(MfaService.name);
  private readonly appName: string;

  constructor(
    private readonly prisma: PrismaService,
    private readonly sessionService: SessionService,
    private readonly authService: AuthService,
    private readonly configService: ConfigService,
  ) {
    this.appName = this.configService.get<string>('MFA_APP_NAME') || 'FullAuthApp';
  }

  /**
   * Generates new TOTP secret, QR code, and single-use hashed backup codes
   */
  async setupMfa(user: User): Promise<MfaSetupPayload> {
    const secret = generateSecret();
    const plainBackupCodes = CryptoUtils.generateBackupCodes(10);
    const hashedBackupCodes = plainBackupCodes.map((code) => CryptoUtils.hashToken(code));

    // Save secret and hashed backup codes (MFA remains disabled until confirmed)
    await this.prisma.user.update({
      where: { id: user.id },
      data: {
        mfaSecret: secret,
        mfaBackupCodes: hashedBackupCodes,
      },
    });

    const otpauthUrl = generateURI({
      issuer: this.appName,
      label: user.email,
      secret,
    });
    const qrCodeUrl = await QRCode.toDataURL(otpauthUrl);

    this.logger.log(`Generated MFA setup for user: ${user.email}`);

    return {
      secret,
      qrCodeUrl,
      backupCodes: plainBackupCodes,
    };
  }

  /**
   * Confirms initial TOTP code to permanently activate MFA for user
   */
  async enableMfa(userId: string, totpCode: string): Promise<boolean> {
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
    });

    if (!user || !user.mfaSecret) {
      throw new CustomAuthError('MFA setup was not initiated', AuthErrorCode.BAD_REQUEST);
    }

    const result = verifySync({
      token: totpCode.trim(),
      secret: user.mfaSecret,
    });

    if (!result?.valid) {
      throw new CustomAuthError('Invalid TOTP verification code', AuthErrorCode.INVALID_MFA_CODE);
    }

    await this.prisma.user.update({
      where: { id: userId },
      data: { isMfaEnabled: true },
    });

    this.logger.log(`MFA successfully enabled for user: ${user.email}`);
    return true;
  }

  /**
   * Challenges and verifies MFA during login (via 6-digit TOTP or one-time backup code)
   */
  async verifyMfaLogin(
    mfaTicket: string,
    code: string,
    req: Request,
    res: Response,
  ): Promise<AuthPayload> {
    const userId = this.authService.verifyMfaTicket(mfaTicket);

    if (!userId) {
      throw new InvalidTokenError('MFA ticket has expired or is invalid');
    }

    const user = await this.prisma.user.findUnique({
      where: { id: userId },
    });

    if (!user || !user.isMfaEnabled || !user.mfaSecret) {
      throw new InvalidTokenError('User or MFA state is invalid');
    }

    const trimmedCode = code.trim();
    let isCodeValid = false;

    // 1. Try TOTP code verification
    if (trimmedCode.length === 6 && /^\d+$/.test(trimmedCode)) {
      const result = verifySync({
        token: trimmedCode,
        secret: user.mfaSecret,
      });
      isCodeValid = Boolean(result?.valid);
    }

    // 2. If not valid TOTP, check if it is a valid single-use backup code
    if (!isCodeValid && user.mfaBackupCodes && user.mfaBackupCodes.length > 0) {
      const hashedAttempt = CryptoUtils.hashToken(trimmedCode.toUpperCase());
      const backupIndex = user.mfaBackupCodes.indexOf(hashedAttempt);

      if (backupIndex !== -1) {
        isCodeValid = true;
        // Consume the backup code so it cannot be reused
        const updatedBackupCodes = [...user.mfaBackupCodes];
        updatedBackupCodes.splice(backupIndex, 1);

        await this.prisma.user.update({
          where: { id: user.id },
          data: { mfaBackupCodes: updatedBackupCodes },
        });

        this.logger.log(`Backup code used by user: ${user.email}. Remaining codes: ${updatedBackupCodes.length}`);
      }
    }

    if (!isCodeValid) {
      throw new CustomAuthError('Invalid MFA code or backup code', AuthErrorCode.INVALID_MFA_CODE);
    }

    // Successful MFA challenge: issue full session and secure cookie
    await this.sessionService.createSession(user.id, req, res);

    return {
      user: {
        ...user,
        emailVerified: Boolean(user.emailVerified),
        createdAt: user.createdAt.toISOString(),
      },
      requiresMfa: false,
      mfaTicket: null,
    };
  }

  /**
   * Disables MFA for authenticated user with TOTP or backup code confirmation
   */
  async disableMfa(userId: string, code: string): Promise<boolean> {
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
    });

    if (!user || !user.isMfaEnabled || !user.mfaSecret) {
      return true;
    }

    const trimmedCode = code.trim();
    let isCodeValid = false;

    if (trimmedCode.length === 6 && /^\d+$/.test(trimmedCode)) {
      const result = verifySync({
        token: trimmedCode,
        secret: user.mfaSecret,
      });
      isCodeValid = Boolean(result?.valid);
    }

    if (!isCodeValid && user.mfaBackupCodes) {
      const hashedAttempt = CryptoUtils.hashToken(trimmedCode.toUpperCase());
      isCodeValid = user.mfaBackupCodes.includes(hashedAttempt);
    }

    if (!isCodeValid) {
      throw new CustomAuthError('Invalid TOTP or backup code to disable MFA', AuthErrorCode.INVALID_MFA_CODE);
    }

    await this.prisma.user.update({
      where: { id: userId },
      data: {
        isMfaEnabled: false,
        mfaSecret: null,
        mfaBackupCodes: [],
      },
    });

    this.logger.log(`MFA successfully disabled for user: ${user.email}`);
    return true;
  }
}
