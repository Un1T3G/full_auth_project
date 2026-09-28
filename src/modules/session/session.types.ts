import { ObjectType, Field, ID } from '@nestjs/graphql';

@ObjectType('Session')
export class SessionType {
  @Field(() => ID)
  id: string;

  @Field(() => String, { nullable: true })
  ipAddress?: string | null;

  @Field(() => String, { nullable: true })
  userAgent?: string | null;

  @Field(() => String)
  expiresAt: string;

  @Field(() => String)
  createdAt: string;

  @Field(() => Boolean, { nullable: true })
  isCurrent?: boolean;
}
