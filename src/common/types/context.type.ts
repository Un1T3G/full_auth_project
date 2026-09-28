import { Request, Response } from 'express';
import { User, Session } from '@prisma/client';

export interface GqlContext {
  req: Request & {
    user?: User;
    session?: Session;
    clientIp?: string;
  };
  res: Response;
}
