import { CanActivate, ExecutionContext, Injectable } from '@nestjs/common';
import { GqlExecutionContext } from '@nestjs/graphql';
import { UnverifiedEmailError, UnauthenticatedError } from '../errors/auth.errors';

@Injectable()
export class EmailVerifiedGuard implements CanActivate {
  canActivate(context: ExecutionContext): boolean {
    const ctx = GqlExecutionContext.create(context);
    const req = ctx.getContext().req;
    const user = req?.user;

    if (!user) {
      throw new UnauthenticatedError();
    }

    if (!user.emailVerified) {
      throw new UnverifiedEmailError();
    }

    return true;
  }
}
