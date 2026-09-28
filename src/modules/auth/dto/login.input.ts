import { InputType, Field } from '@nestjs/graphql';
import { IsEmail, IsNotEmpty, IsString } from 'class-validator';

@InputType()
export class LoginInput {
  @Field(() => String)
  @IsEmail({}, { message: 'Invalid email address' })
  @IsNotEmpty({ message: 'Email cannot be empty' })
  email: string;

  @Field(() => String)
  @IsString()
  @IsNotEmpty({ message: 'Password cannot be empty' })
  password: string;
}
