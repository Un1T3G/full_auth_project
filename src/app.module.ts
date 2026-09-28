import { Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { GraphQLModule } from '@nestjs/graphql';
import { ApolloDriver, ApolloDriverConfig } from '@nestjs/apollo';
import { ApolloServerPluginLandingPageLocalDefault } from '@apollo/server/plugin/landingPage/default';
import { join } from 'path';
import { PrismaModule } from './prisma/prisma.module';
import { MailModule } from './modules/mail/mail.module';
import { SessionModule } from './modules/session/session.module';
import { UserModule } from './modules/user/user.module';
import { AuthModule } from './modules/auth/auth.module';
import { MfaModule } from './modules/mfa/mfa.module';
import { OAuthModule } from './modules/oauth/oauth.module';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { GraphQLError } from 'graphql';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
      envFilePath: '.env',
    }),
    GraphQLModule.forRootAsync<ApolloDriverConfig>({
      driver: ApolloDriver,
      inject: [ConfigService],
      useFactory: (configService: ConfigService) => {
        const isProduction = configService.get<string>('NODE_ENV') === 'production';
        return {
          autoSchemaFile: join(process.cwd(), 'src/schema.gql'),
          sortSchema: true,
          playground: false,
          plugins: [
            ApolloServerPluginLandingPageLocalDefault({
              embed: true,
              includeCookies: true,
            }),
          ],
          context: ({ req, res }: { req: any; res: any }) => ({ req, res }),
          formatError: (formattedError, error) => {
            const originalError = (error as any)?.originalError;
            const code =
              formattedError.extensions?.code ||
              originalError?.extensions?.code ||
              'INTERNAL_SERVER_ERROR';

            return {
              message: formattedError.message,
              extensions: {
                code,
                timestamp: formattedError.extensions?.timestamp || new Date().toISOString(),
                ...(formattedError.extensions?.mfaTicket
                  ? { mfaTicket: formattedError.extensions.mfaTicket }
                  : {}),
                ...(!isProduction && formattedError.extensions?.stacktrace
                  ? { stacktrace: formattedError.extensions.stacktrace }
                  : {}),
              },
            };
          },
        };
      },
    }),
    PrismaModule,
    MailModule,
    SessionModule,
    UserModule,
    AuthModule,
    MfaModule,
    OAuthModule,
  ],
  controllers: [AppController],
  providers: [AppService],
})
export class AppModule {}
