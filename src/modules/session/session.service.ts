import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Request, Response } from 'express';
import { PrismaService } from '../../prisma/prisma.service';
import { CryptoUtils } from '../../common/utils/crypto.utils';
import { Session, User } from '@prisma/client';

@Injectable()
export class SessionService {
  private readonly logger = new Logger(SessionService.name);
  private readonly cookieName: string;
  private readonly ttlDays: number;
  private readonly isProduction: boolean;

  constructor(
    private readonly prisma: PrismaService,
    private readonly configService: ConfigService,
  ) {
    this.cookieName = this.configService.get<string>('SESSION_COOKIE_NAME') || 'auth_session';
    this.ttlDays = Number(this.configService.get<number>('SESSION_TTL_DAYS')) || 7;
    this.isProduction = this.configService.get<string>('NODE_ENV') === 'production';
  }

  getCookieName(): string {
    return this.cookieName;
  }

  /**
   * Extracts client IP address safely from headers or socket
   */
  getClientIp(req: Request): string {
    const forwarded = req.headers['x-forwarded-for'];
    if (typeof forwarded === 'string') {
      return forwarded.split(',')[0].trim();
    }
    if (Array.isArray(forwarded) && forwarded.length > 0) {
      return forwarded[0].trim();
    }
    return req.socket.remoteAddress || 'unknown';
  }

  /**
   * Extracts client User-Agent string
   */
  getUserAgent(req: Request): string {
    return (req.headers['user-agent'] as string) || 'unknown';
  }

  /**
   * Creates a new session in database and sets HTTP-Only cookie on response
   */
  async createSession(userId: string, req: Request, res?: Response): Promise<Session> {
    const sessionToken = CryptoUtils.generateRandomToken(48);
    const ipAddress = this.getClientIp(req);
    const userAgent = this.getUserAgent(req);

    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + this.ttlDays);

    const session = await this.prisma.session.create({
      data: {
        sessionToken,
        userId,
        ipAddress,
        userAgent,
        expiresAt,
      },
    });

    if (res) {
      this.setSessionCookie(res, sessionToken, expiresAt);
    }

    return session;
  }

  /**
   * Sets HTTP-Only, Secure, SameSite cookie
   */
  setSessionCookie(res: Response, token: string, expiresAt: Date) {
    res.cookie(this.cookieName, token, {
      httpOnly: true,
      secure: this.isProduction,
      sameSite: this.isProduction ? 'none' : 'lax',
      expires: expiresAt,
      path: '/',
    });
  }

  /**
   * Clears session cookie
   */
  clearSessionCookie(res: Response) {
    res.clearCookie(this.cookieName, {
      httpOnly: true,
      secure: this.isProduction,
      sameSite: this.isProduction ? 'none' : 'lax',
      path: '/',
    });
  }

  /**
   * Finds an active valid session by token and returns session with user
   */
  async findValidSession(token: string): Promise<(Session & { user: User }) | null> {
    if (!token) return null;

    const session = await this.prisma.session.findUnique({
      where: { sessionToken: token },
      include: { user: true },
    });

    if (!session) {
      return null;
    }

    // Check expiration
    if (session.expiresAt.getTime() <= Date.now()) {
      await this.prisma.session.delete({ where: { id: session.id } }).catch(() => null);
      return null;
    }

    return session;
  }

  /**
   * Destroys a session by token and clears cookie
   */
  async destroySession(token: string, res?: Response): Promise<boolean> {
    try {
      await this.prisma.session.deleteMany({
        where: { sessionToken: token },
      });
    } catch (e) {
      this.logger.warn(`Could not delete session: ${e}`);
    }

    if (res) {
      this.clearSessionCookie(res);
    }
    return true;
  }

  /**
   * Revokes a specific session by ID for a user
   */
  async revokeSessionById(sessionId: string, userId: string): Promise<boolean> {
    const result = await this.prisma.session.deleteMany({
      where: {
        id: sessionId,
        userId,
      },
    });
    return result.count > 0;
  }

  /**
   * Revokes all active sessions for a user (e.g. on password reset or logout from all devices)
   */
  async revokeAllUserSessions(userId: string, res?: Response): Promise<boolean> {
    await this.prisma.session.deleteMany({
      where: { userId },
    });

    if (res) {
      this.clearSessionCookie(res);
    }
    return true;
  }

  /**
   * Lists all sessions of a user
   */
  async getUserSessions(userId: string, currentSessionId?: string): Promise<Session[]> {
    return this.prisma.session.findMany({
      where: {
        userId,
        expiresAt: { gt: new Date() },
      },
      orderBy: { createdAt: 'desc' },
    });
  }
}
