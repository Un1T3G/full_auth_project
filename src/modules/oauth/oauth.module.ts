import { Module, forwardRef } from '@nestjs/common';
import { OAuthService } from './oauth.service';
import { AuthModule } from '../auth/auth.module';
import { SessionModule } from '../session/session.module';

@Module({
  imports: [forwardRef(() => AuthModule), SessionModule],
  providers: [OAuthService],
  exports: [OAuthService],
})
export class OAuthModule {}
