import { Resolver, Mutation, Query, Args, Context } from '@nestjs/graphql';
import { Inject, forwardRef, UseGuards } from '@nestjs/common';
import { AuthService } from './auth.service';
import { OAuthService } from '../oauth/oauth.service';
import { RegisterInput } from './dto/register.input';
import { LoginInput } from './dto/login.input';
import { AuthPayload } from './dto/auth.payload';
import { SessionType } from '../session/session.types';
import type { GqlContext } from '../../common/types/context.type';
import { GqlAuthGuard } from '../../common/guards/gql-auth.guard';
import { CurrentUser } from '../../common/decorators/current-user.decorator';
import { CurrentSession } from '../../common/decorators/current-session.decorator';
import { Public } from '../../common/decorators/public.decorator';
import type { Session, User } from '@prisma/client';

@Resolver()
export class AuthResolver {
  constructor(
    private readonly authService: AuthService,
    @Inject(forwardRef(() => OAuthService))
    private readonly oauthService: OAuthService,
  ) {}

  @Public()
  @Mutation(() => Boolean, { description: 'Registers a new user' })
  async register(@Args('input') input: RegisterInput): Promise<boolean> {
    return this.authService.register(input);
  }

  @Public()
  @Mutation(() => AuthPayload, { description: 'Logs in user with email and password' })
  async login(
    @Args('input') input: LoginInput,
    @Context() { req, res }: GqlContext,
  ): Promise<AuthPayload> {
    return this.authService.login(input, req, res);
  }

  @Public()
  @Mutation(() => AuthPayload, { description: 'Logs in or registers user via OAuth provider (Google, GitHub)' })
  async loginWithOAuth(
    @Args('provider') provider: string,
    @Args('code') code: string,
    @Context() { req, res }: GqlContext,
  ): Promise<AuthPayload> {
    return this.oauthService.loginWithOAuth(provider, code, req, res);
  }

  @Public()
  @Mutation(() => Boolean, { description: 'Logs out user and clears session' })
  async logout(@Context() { req, res }: GqlContext): Promise<boolean> {
    return this.authService.logout(req, res);
  }

  @Public()
  @Mutation(() => Boolean, { description: 'Verifies email address using confirmation token' })
  async verifyEmail(@Args('token') token: string): Promise<boolean> {
    return this.authService.verifyEmail(token);
  }

  @Public()
  @Mutation(() => Boolean, { description: 'Requests a password reset link to be sent to email' })
  async requestPasswordReset(@Args('email') email: string): Promise<boolean> {
    return this.authService.requestPasswordReset(email);
  }

  @Public()
  @Mutation(() => Boolean, { description: 'Resets password using token and revokes all active sessions' })
  async resetPassword(
    @Args('token') token: string,
    @Args('newPassword') newPassword: string,
  ): Promise<boolean> {
    return this.authService.resetPassword(token, newPassword);
  }

  @Query(() => [SessionType], { name: 'mySessions', description: 'Lists all active sessions for current user' })
  @UseGuards(GqlAuthGuard)
  async mySessions(
    @CurrentUser() user: User,
    @CurrentSession() session?: Session,
  ): Promise<SessionType[]> {
    return this.authService.getMySessions(user, session?.id);
  }

  @Mutation(() => Boolean, { description: 'Revokes a specific user session by id' })
  @UseGuards(GqlAuthGuard)
  async revokeSession(
    @Args('sessionId') sessionId: string,
    @CurrentUser() user: User,
  ): Promise<boolean> {
    return this.authService.revokeSession(sessionId, user.id);
  }

  @Mutation(() => Boolean, { description: 'Logs out from all devices, revoking all sessions' })
  @UseGuards(GqlAuthGuard)
  async logoutAll(
    @CurrentUser() user: User,
    @Context() { res }: GqlContext,
  ): Promise<boolean> {
    return this.authService.logoutAll(user.id, res);
  }
}
