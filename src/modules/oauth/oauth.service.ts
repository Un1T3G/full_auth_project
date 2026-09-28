import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Request, Response } from 'express';
import { PrismaService } from '../../prisma/prisma.service';
import { SessionService } from '../session/session.service';
import { AuthService } from '../auth/auth.service';
import { AuthPayload } from '../auth/dto/auth.payload';
import { AuthErrorCode, CustomAuthError } from '../../common/errors/auth.errors';
import { CryptoUtils } from '../../common/utils/crypto.utils';
import { User, Account } from '@prisma/client';

interface OAuthUserProfile {
  providerAccountId: string;
  email: string;
  name?: string;
  accessToken?: string;
  refreshToken?: string;
  expiresAt?: number;
}

@Injectable()
export class OAuthService {
  private readonly logger = new Logger(OAuthService.name);

  constructor(
    private readonly prisma: PrismaService,
    private readonly sessionService: SessionService,
    private readonly authService: AuthService,
    private readonly configService: ConfigService,
  ) {}

  /**
   * Exchanges code with provider, retrieves user profile, links account, and handles MFA
   */
  async loginWithOAuth(
    provider: string,
    code: string,
    req: Request,
    res: Response,
  ): Promise<AuthPayload> {
    const normalizedProvider = provider.toLowerCase().trim();
    let profile: OAuthUserProfile;

    if (normalizedProvider === 'google') {
      profile = await this.resolveGoogleProfile(code);
    } else if (normalizedProvider === 'github') {
      profile = await this.resolveGitHubProfile(code);
    } else {
      throw new CustomAuthError(
        `Unsupported OAuth provider: ${provider}`,
        AuthErrorCode.BAD_REQUEST,
      );
    }

    const normalizedEmail = CryptoUtils.normalizeEmail(profile.email);

    // 1. Check if account with provider + providerAccountId already exists
    const account = await this.prisma.account.findUnique({
      where: {
        provider_providerAccountId: {
          provider: normalizedProvider,
          providerAccountId: profile.providerAccountId,
        },
      },
      include: { user: true },
    });

    let user: User | null = account?.user ?? null;

    // 2. If account does not exist, find user by email or create new user
    if (!user) {
      user = await this.prisma.user.findUnique({
        where: { email: normalizedEmail },
      });

      if (!user) {
        user = await this.prisma.user.create({
          data: {
            email: normalizedEmail,
            name: profile.name || null,
            emailVerified: new Date(), // OAuth verified email
            passwordHash: null,
            isMfaEnabled: false,
          },
        });
        this.logger.log(`Created new user via ${normalizedProvider}: ${normalizedEmail}`);
      }

      // Link Account
      await this.prisma.account.create({
        data: {
          userId: user.id,
          provider: normalizedProvider,
          providerAccountId: profile.providerAccountId,
          accessToken: profile.accessToken,
          refreshToken: profile.refreshToken,
          expiresAt: profile.expiresAt,
        },
      });
      this.logger.log(`Linked ${normalizedProvider} account for user: ${normalizedEmail}`);
    } else if (account) {
      // Update tokens if provided
      await this.prisma.account.update({
        where: { id: account.id },
        data: {
          accessToken: profile.accessToken ?? account.accessToken,
          refreshToken: profile.refreshToken ?? account.refreshToken,
          expiresAt: profile.expiresAt ?? account.expiresAt,
        },
      });
    }

    // 3. Check if user has MFA enabled: issue MFA challenge ticket
    if (user.isMfaEnabled) {
      const mfaTicket = this.authService.generateMfaTicket(user.id);
      return {
        user: null,
        requiresMfa: true,
        mfaTicket,
      };
    }

    // 4. Create session and set cookie
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

  private async resolveGoogleProfile(code: string): Promise<OAuthUserProfile> {
    const clientId = this.configService.get<string>('GOOGLE_CLIENT_ID');
    const clientSecret = this.configService.get<string>('GOOGLE_CLIENT_SECRET');
    const frontendUrl = this.configService.get<string>('FRONTEND_URL') || 'http://localhost:3000';
    const redirectUri = `${frontendUrl}/auth/callback/google`;

    if (!clientId || !clientSecret) {
      // In dev mode when credentials are not configured, allow mock test payload if in test/development
      if (this.configService.get<string>('NODE_ENV') !== 'production' && code.startsWith('mock:')) {
        const mockEmail = code.replace('mock:', '');
        return {
          providerAccountId: `google_${mockEmail}`,
          email: mockEmail,
          name: 'Google Mock User',
        };
      }
      throw new CustomAuthError(
        'Google OAuth credentials are not configured in environment variables',
        AuthErrorCode.BAD_REQUEST,
      );
    }

    try {
      const tokenResponse = await fetch('https://oauth2.googleapis.com/token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          code,
          client_id: clientId,
          client_secret: clientSecret,
          redirect_uri: redirectUri,
          grant_type: 'authorization_code',
        }),
      });

      const tokenData = await tokenResponse.json();
      if (!tokenResponse.ok) {
        throw new Error(tokenData.error_description || 'Failed to exchange Google token');
      }

      const userResponse = await fetch('https://www.googleapis.com/oauth2/v2/userinfo', {
        headers: { Authorization: `Bearer ${tokenData.access_token}` },
      });

      const userData = await userResponse.json();

      return {
        providerAccountId: userData.id,
        email: userData.email,
        name: userData.name,
        accessToken: tokenData.access_token,
        refreshToken: tokenData.refresh_token,
        expiresAt: tokenData.expires_in ? Math.floor(Date.now() / 1000) + tokenData.expires_in : undefined,
      };
    } catch (err: any) {
      this.logger.error('Google OAuth error:', err);
      throw new CustomAuthError(`Google authentication failed: ${err.message}`, AuthErrorCode.INVALID_TOKEN);
    }
  }

  private async resolveGitHubProfile(code: string): Promise<OAuthUserProfile> {
    const clientId = this.configService.get<string>('GITHUB_CLIENT_ID');
    const clientSecret = this.configService.get<string>('GITHUB_CLIENT_SECRET');

    if (!clientId || !clientSecret) {
      if (this.configService.get<string>('NODE_ENV') !== 'production' && code.startsWith('mock:')) {
        const mockEmail = code.replace('mock:', '');
        return {
          providerAccountId: `github_${mockEmail}`,
          email: mockEmail,
          name: 'GitHub Mock User',
        };
      }
      throw new CustomAuthError(
        'GitHub OAuth credentials are not configured in environment variables',
        AuthErrorCode.BAD_REQUEST,
      );
    }

    try {
      const tokenResponse = await fetch('https://github.com/login/oauth/access_token', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Accept: 'application/json',
        },
        body: JSON.stringify({
          client_id: clientId,
          client_secret: clientSecret,
          code,
        }),
      });

      const tokenData = await tokenResponse.json();
      if (!tokenResponse.ok || tokenData.error) {
        throw new Error(tokenData.error_description || 'Failed to exchange GitHub token');
      }

      const userResponse = await fetch('https://api.github.com/user', {
        headers: {
          Authorization: `Bearer ${tokenData.access_token}`,
          Accept: 'application/vnd.github+json',
        },
      });

      const userData = await userResponse.json();

      let email = userData.email;
      if (!email) {
        // Fetch primary email from /user/emails
        const emailsResponse = await fetch('https://api.github.com/user/emails', {
          headers: {
            Authorization: `Bearer ${tokenData.access_token}`,
            Accept: 'application/vnd.github+json',
          },
        });
        const emailsData = await emailsResponse.json();
        const primaryEmail = emailsData.find((e: any) => e.primary && e.verified);
        email = primaryEmail ? primaryEmail.email : emailsData[0]?.email;
      }

      return {
        providerAccountId: String(userData.id),
        email,
        name: userData.name || userData.login,
        accessToken: tokenData.access_token,
      };
    } catch (err: any) {
      this.logger.error('GitHub OAuth error:', err);
      throw new CustomAuthError(`GitHub authentication failed: ${err.message}`, AuthErrorCode.INVALID_TOKEN);
    }
  }
}
