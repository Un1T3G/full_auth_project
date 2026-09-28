import { CanActivate, ExecutionContext, Injectable } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { GqlExecutionContext } from '@nestjs/graphql';
import { SessionService } from '../../modules/session/session.service';
import { IS_PUBLIC_KEY } from '../decorators/public.decorator';
import { UnauthenticatedError } from '../errors/auth.errors';

@Injectable()
export class GqlAuthGuard implements CanActivate {
  constructor(
    private readonly reflector: Reflector,
    private readonly sessionService: SessionService,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const isPublic = this.reflector.getAllAndOverride<boolean>(IS_PUBLIC_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);

    const ctx = GqlExecutionContext.create(context);
    const req = ctx.getContext().req;

    if (!req) {
      return isPublic;
    }

    // Extract token from Cookie or Authorization Bearer header
    const cookieName = this.sessionService.getCookieName();
    let token = req.cookies?.[cookieName];

    if (!token && req.headers?.authorization) {
      const parts = req.headers.authorization.split(' ');
      if (parts.length === 2 && /^Bearer$/i.test(parts[0])) {
        token = parts[1];
      }
    }

    if (!token) {
      if (isPublic) {
        return true;
      }
      throw new UnauthenticatedError();
    }

    const sessionWithUser = await this.sessionService.findValidSession(token);

    if (!sessionWithUser) {
      if (isPublic) {
        return true;
      }
      throw new UnauthenticatedError('Session has expired or is invalid');
    }

    // Attach user and session to request context
    req.user = sessionWithUser.user;
    req.session = sessionWithUser;

    return true;
  }
}
