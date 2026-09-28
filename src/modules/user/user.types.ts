import { ObjectType, Field, ID, registerEnumType } from '@nestjs/graphql';
import { Role } from '@prisma/client';

registerEnumType(Role, {
  name: 'Role',
  description: 'User access role',
});

@ObjectType('User')
export class UserType {
  @Field(() => ID)
  id: string;

  @Field(() => String)
  email: string;

  @Field(() => String, { nullable: true })
  name?: string | null;

  @Field(() => Role)
  role: Role;

  @Field(() => Boolean)
  emailVerified: boolean;

  @Field(() => Boolean)
  isMfaEnabled: boolean;

  @Field(() => String)
  createdAt: string;
}
