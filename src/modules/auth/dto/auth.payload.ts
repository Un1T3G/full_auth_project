import { ObjectType, Field } from '@nestjs/graphql';
import { UserType } from '../../user/user.types';

@ObjectType('AuthPayload')
export class AuthPayload {
  @Field(() => UserType, { nullable: true })
  user?: UserType | null;

  @Field(() => Boolean, { nullable: true })
  requiresMfa?: boolean;

  @Field(() => String, { nullable: true })
  mfaTicket?: string | null;
}
