import { CanActivate, ExecutionContext, Injectable } from '@nestjs/common';
import { GqlExecutionContext } from '@nestjs/graphql';
import { UnauthenticatedError, CustomAuthError, AuthErrorCode } from '../errors/auth.errors';

@Injectable()
export class MfaGuard implements CanActivate {
  canActivate(context: ExecutionContext): boolean {
    const ctx = GqlExecutionContext.create(context);
    const req = ctx.getContext().req;
    const user = req?.user;

    if (!user) {
      throw new UnauthenticatedError();
    }

    if (user.isMfaEnabled && !user.mfaSecret) {
      throw new CustomAuthError(
        'MFA is enabled on this account but not properly configured',
        AuthErrorCode.MFA_REQUIRED,
      );
    }

    return true;
  }
}
