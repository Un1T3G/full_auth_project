import { Module, forwardRef } from '@nestjs/common';
import { MfaService } from './mfa.service';
import { MfaResolver } from './mfa.resolver';
import { AuthModule } from '../auth/auth.module';
import { UserModule } from '../user/user.module';

@Module({
  imports: [forwardRef(() => AuthModule), UserModule],
  providers: [MfaService, MfaResolver],
  exports: [MfaService],
})
export class MfaModule {}
