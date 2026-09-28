import { createParamDecorator, ExecutionContext } from '@nestjs/common';
import { GqlExecutionContext } from '@nestjs/graphql';
import { Session } from '@prisma/client';

export const CurrentSession = createParamDecorator(
  (data: keyof Session | undefined, context: ExecutionContext) => {
    const ctx = GqlExecutionContext.create(context);
    const req = ctx.getContext().req;
    const session = req?.session;

    if (!session) {
      return null;
    }

    return data ? session[data] : session;
  },
);
