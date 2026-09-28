import { Resolver, Mutation, Args, Context } from '@nestjs/graphql';
import { UseGuards } from '@nestjs/common';
import { MfaService } from './mfa.service';
import { MfaSetupPayload } from './dto/mfa-setup.payload';
import { AuthPayload } from '../auth/dto/auth.payload';
import { GqlAuthGuard } from '../../common/guards/gql-auth.guard';
import { CurrentUser } from '../../common/decorators/current-user.decorator';
import { Public } from '../../common/decorators/public.decorator';
import type { GqlContext } from '../../common/types/context.type';
import type { User } from '@prisma/client';

@Resolver()
export class MfaResolver {
  constructor(private readonly mfaService: MfaService) {}

  @Mutation(() => MfaSetupPayload, { description: 'Generates TOTP secret, QR code, and backup codes' })
  @UseGuards(GqlAuthGuard)
  async setupMfa(@CurrentUser() user: User): Promise<MfaSetupPayload> {
    return this.mfaService.setupMfa(user);
  }

  @Mutation(() => Boolean, { description: 'Verifies first TOTP code and activates MFA for user' })
  @UseGuards(GqlAuthGuard)
  async enableMfa(
    @Args('totpCode') totpCode: string,
    @CurrentUser() user: User,
  ): Promise<boolean> {
    return this.mfaService.enableMfa(user.id, totpCode);
  }

  @Public()
  @Mutation(() => AuthPayload, { description: 'Completes 2-factor login challenge via TOTP or backup code' })
  async verifyMfaLogin(
    @Args('mfaTicket') mfaTicket: string,
    @Args('code') code: string,
    @Context() { req, res }: GqlContext,
  ): Promise<AuthPayload> {
    return this.mfaService.verifyMfaLogin(mfaTicket, code, req, res);
  }

  @Mutation(() => Boolean, { description: 'Disables MFA for current user with code verification' })
  @UseGuards(GqlAuthGuard)
  async disableMfa(
    @Args('totpCode') totpCode: string,
    @CurrentUser() user: User,
  ): Promise<boolean> {
    return this.mfaService.disableMfa(user.id, totpCode);
  }
}
