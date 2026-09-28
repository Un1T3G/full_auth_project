import { Resolver, Query, ResolveField, Root } from '@nestjs/graphql';
import { UseGuards } from '@nestjs/common';
import { UserType } from './user.types';
import { GqlAuthGuard } from '../../common/guards/gql-auth.guard';
import { CurrentUser } from '../../common/decorators/current-user.decorator';
import type { User } from '@prisma/client';

@Resolver(() => UserType)
export class UserResolver {
  @Query(() => UserType, { name: 'me', nullable: true })
  @UseGuards(GqlAuthGuard)
  async me(@CurrentUser() user: User | null): Promise<User | null> {
    return user;
  }

  @ResolveField(() => Boolean)
  emailVerified(@Root() user: User): boolean {
    return Boolean(user.emailVerified);
  }

  @ResolveField(() => String)
  createdAt(@Root() user: User): string {
    return user.createdAt instanceof Date ? user.createdAt.toISOString() : String(user.createdAt);
  }
}
