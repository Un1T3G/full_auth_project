import { Module, forwardRef } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthResolver } from './auth.resolver';
import { UserModule } from '../user/user.module';
import { OAuthModule } from '../oauth/oauth.module';

@Module({
  imports: [UserModule, forwardRef(() => OAuthModule)],
  providers: [AuthService, AuthResolver],
  exports: [AuthService],
})
export class AuthModule {}
