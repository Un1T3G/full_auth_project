import { ObjectType, Field } from '@nestjs/graphql';

@ObjectType('MfaSetupPayload')
export class MfaSetupPayload {
  @Field(() => String, { description: 'TOTP secret key for manual entry' })
  secret: string;

  @Field(() => String, { description: 'Base64 Data URL for QR code' })
  qrCodeUrl: string;

  @Field(() => [String], { description: 'One-time plaintext backup codes (shown only once)' })
  backupCodes: string[];
}
