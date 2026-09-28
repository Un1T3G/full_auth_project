import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Request, Response } from 'express';
import { PrismaService } from '../../prisma/prisma.service';
import { SessionService } from '../session/session.service';
import { MailService } from '../mail/mail.service';
import { CryptoUtils } from '../../common/utils/crypto.utils';
import { RegisterInput } from './dto/register.input';
import { LoginInput } from './dto/login.input';
import { AuthPayload } from './dto/auth.payload';
import {
  AuthErrorCode,
  CustomAuthError,
  InvalidCredentialsError,
  InvalidTokenError,
  UserAlreadyExistsError,
} from '../../common/errors/auth.errors';
import { Session, User } from '@prisma/client';
import { SessionType } from '../session/session.types';
import * as crypto from 'crypto';

@Injectable()
export class AuthService {
  private readonly logger = new Logger(AuthService.name);
  private readonly mfaTicketSecret: string;

  constructor(
    private readonly prisma: PrismaService,
    private readonly sessionService: SessionService,
    private readonly mailService: MailService,
    private readonly configService: ConfigService,
  ) {
    this.mfaTicketSecret =
      this.configService.get<string>('MFA_TICKET_SECRET') || 'default-mfa-ticket-secret-key-32-chars';
  }

  /**
   * Registers a new user with Argon2id hashed password and sends verification email
   */
  async register(input: RegisterInput): Promise<boolean> {
    const normalizedEmail = CryptoUtils.normalizeEmail(input.email);

    if (!CryptoUtils.isStrongPassword(input.password)) {
      throw new CustomAuthError(
        'Password must be at least 8 characters long and contain at least one uppercase letter, one digit, and one special character',
        AuthErrorCode.BAD_REQUEST,
      );
    }

    const existingUser = await this.prisma.user.findUnique({
      where: { email: normalizedEmail },
    });

    if (existingUser) {
      throw new UserAlreadyExistsError();
    }

    const passwordHash = await CryptoUtils.hashPassword(input.password);

    const user = await this.prisma.user.create({
      data: {
        email: normalizedEmail,
        passwordHash,
        name: input.name ? input.name.trim() : null,
        emailVerified: null,
        isMfaEnabled: false,
      },
    });

    // Create 24-hour email verification token
    const token = CryptoUtils.generateRandomToken(32);
    const expiresAt = new Date();
    expiresAt.setHours(expiresAt.getHours() + 24);

    await this.prisma.verificationToken.create({
      data: {
        token,
        email: normalizedEmail,
        userId: user.id,
        expiresAt,
      },
    });

    await this.mailService.sendVerificationEmail(normalizedEmail, token);
    this.logger.log(`New user registered and verification email sent: ${normalizedEmail}`);
    return true;
  }

  /**
   * Verifies user email with token
   */
  async verifyEmail(token: string): Promise<boolean> {
    const record = await this.prisma.verificationToken.findUnique({
      where: { token },
      include: { user: true },
    });

    if (!record) {
      throw new InvalidTokenError('Verification token not found or already used');
    }

    if (record.expiresAt.getTime() <= Date.now()) {
      await this.prisma.verificationToken.delete({ where: { id: record.id } }).catch(() => null);
      throw new InvalidTokenError('Verification token has expired');
    }

    await this.prisma.$transaction([
      this.prisma.user.update({
        where: { id: record.userId },
        data: { emailVerified: new Date() },
      }),
      this.prisma.verificationToken.delete({
        where: { id: record.id },
      }),
    ]);

    this.logger.log(`Email successfully verified for user: ${record.email}`);
    return true;
  }

  /**
   * Requests a password reset link (prevents account enumeration)
   */
  async requestPasswordReset(email: string): Promise<boolean> {
    const normalizedEmail = CryptoUtils.normalizeEmail(email);

    const user = await this.prisma.user.findUnique({
      where: { email: normalizedEmail },
    });

    if (!user) {
      // Return true to prevent account enumeration
      return true;
    }

    // Clean up any existing tokens for this user
    await this.prisma.passwordResetToken.deleteMany({
      where: { userId: user.id },
    });

    // Create 20-minute reset token
    const token = CryptoUtils.generateRandomToken(32);
    const expiresAt = new Date();
    expiresAt.setMinutes(expiresAt.getMinutes() + 20);

    await this.prisma.passwordResetToken.create({
      data: {
        token,
        userId: user.id,
        expiresAt,
      },
    });

    await this.mailService.sendPasswordResetEmail(normalizedEmail, token);
    this.logger.log(`Password reset link sent to: ${normalizedEmail}`);
    return true;
  }

  /**
   * Resets password using valid token and revokes ALL active sessions
   */
  async resetPassword(token: string, newPassword: string): Promise<boolean> {
    if (!CryptoUtils.isStrongPassword(newPassword)) {
      throw new CustomAuthError(
        'Password must be at least 8 characters long and contain at least one uppercase letter, one digit, and one special character',
        AuthErrorCode.BAD_REQUEST,
      );
    }

    const resetRecord = await this.prisma.passwordResetToken.findUnique({
      where: { token },
      include: { user: true },
    });

    if (!resetRecord) {
      throw new InvalidTokenError('Reset token not found or already used');
    }

    if (resetRecord.expiresAt.getTime() <= Date.now()) {
      await this.prisma.passwordResetToken.delete({ where: { id: resetRecord.id } }).catch(() => null);
      throw new InvalidTokenError('Reset token has expired');
    }

    const newPasswordHash = await CryptoUtils.hashPassword(newPassword);

    // Update password, delete token, and revoke ALL active sessions
    await this.prisma.$transaction([
      this.prisma.user.update({
        where: { id: resetRecord.userId },
        data: { passwordHash: newPasswordHash },
      }),
      this.prisma.passwordResetToken.delete({
        where: { id: resetRecord.id },
      }),
      this.prisma.session.deleteMany({
        where: { userId: resetRecord.userId },
      }),
    ]);

    this.logger.log(`Password reset successfully for user: ${resetRecord.user.email}. All sessions revoked.`);
    return true;
  }

  /**
   * Authenticates user via email and password, creates session or triggers MFA challenge
   */
  async login(input: LoginInput, req: Request, res: Response): Promise<AuthPayload> {
    const normalizedEmail = CryptoUtils.normalizeEmail(input.email);

    const user = await this.prisma.user.findUnique({
      where: { email: normalizedEmail },
    });

    if (!user || !user.passwordHash) {
      throw new InvalidCredentialsError();
    }

    const isPasswordValid = await CryptoUtils.verifyPassword(user.passwordHash, input.password);

    if (!isPasswordValid) {
      throw new InvalidCredentialsError();
    }

    // If MFA is enabled, issue temporary MFA ticket and challenge user
    if (user.isMfaEnabled) {
      const mfaTicket = this.generateMfaTicket(user.id);
      return {
        user: null,
        requiresMfa: true,
        mfaTicket,
      };
    }

    // MFA not enabled: create session and set HTTP-only cookie
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
   * Logs out user by destroying current session and clearing cookie
   */
  async logout(req: Request, res: Response): Promise<boolean> {
    const cookieName = this.sessionService.getCookieName();
    let token = req.cookies?.[cookieName];

    if (!token && req.headers?.authorization) {
      const parts = req.headers.authorization.split(' ');
      if (parts.length === 2 && /^Bearer$/i.test(parts[0])) {
        token = parts[1];
      }
    }

    if (token) {
      await this.sessionService.destroySession(token, res);
    } else {
      this.sessionService.clearSessionCookie(res);
    }

    return true;
  }

  /**
   * Fetches active sessions for the current user
   */
  async getMySessions(user: User, currentSessionId?: string): Promise<SessionType[]> {
    const sessions = await this.sessionService.getUserSessions(user.id);

    return sessions.map((s) => ({
      id: s.id,
      ipAddress: s.ipAddress,
      userAgent: s.userAgent,
      expiresAt: s.expiresAt.toISOString(),
      createdAt: s.createdAt.toISOString(),
      isCurrent: s.id === currentSessionId,
    }));
  }

  /**
   * Revokes a specific session by ID
   */
  async revokeSession(sessionId: string, userId: string): Promise<boolean> {
    return this.sessionService.revokeSessionById(sessionId, userId);
  }

  /**
   * Revokes all sessions of user
   */
  async logoutAll(userId: string, res: Response): Promise<boolean> {
    return this.sessionService.revokeAllUserSessions(userId, res);
  }

  /**
   * Generates a signed, time-limited MFA challenge ticket
   */
  generateMfaTicket(userId: string, ttlSeconds = 300): string {
    const expiresAt = Date.now() + ttlSeconds * 1000;
    const payload = `${userId}:${expiresAt}`;
    const signature = crypto
      .createHmac('sha256', this.mfaTicketSecret)
      .update(payload)
      .digest('hex');

    return Buffer.from(`${payload}:${signature}`).toString('base64url');
  }

  /**
   * Validates MFA ticket and extracts userId if valid
   */
  verifyMfaTicket(ticket: string): string | null {
    try {
      const decoded = Buffer.from(ticket, 'base64url').toString('utf8');
      const [userId, expiresAtStr, signature] = decoded.split(':');

      if (!userId || !expiresAtStr || !signature) {
        return null;
      }

      const expiresAt = Number(expiresAtStr);
      if (Date.now() > expiresAt) {
        return null;
      }

      const expectedSignature = crypto
        .createHmac('sha256', this.mfaTicketSecret)
        .update(`${userId}:${expiresAtStr}`)
        .digest('hex');

      const expectedBuffer = Buffer.from(expectedSignature);
      const signatureBuffer = Buffer.from(signature);

      if (
        expectedBuffer.length !== signatureBuffer.length ||
        !crypto.timingSafeEqual(expectedBuffer, signatureBuffer)
      ) {
        return null;
      }

      return userId;
    } catch {
      return null;
    }
  }
}
