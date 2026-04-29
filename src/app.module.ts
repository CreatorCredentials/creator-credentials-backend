import {
  MiddlewareConsumer,
  Module,
  NestModule,
  UnauthorizedException,
} from '@nestjs/common';
import { type Request, type Response } from 'express';
import type { WithAuthProp } from '@clerk/clerk-sdk-node';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { ScheduleModule } from '@nestjs/schedule';
import { ConfigModule } from '@nestjs/config';
import { TypeOrmModule } from '@nestjs/typeorm';
import { HealthModule } from './health/health.module';
import { UsersModule } from './users/users.module';
import LogsMiddleware from './config/logs.middleware';
import { ClerkExpressWithAuth } from '@clerk/clerk-sdk-node';
import { NextFunction } from 'express';
import { CredentialsModule } from './credentials/credentials.module';
import { MocksModule } from './mocks/mocks.module';
import { ConnectionsModule } from './connections/connections.module';
import { TemplatesModule } from './templates/templates.module';
import { KeypairChallengeModule } from './keypair-challenge/keypair-challenge.module';
import { CertChallengeModule } from './cert-challenge/cert-challenge.module';
import { WebhooksModule } from './webhooks/webhooks.module';

@Module({
  imports: [
    ScheduleModule.forRoot(),
    ConfigModule.forRoot({ isGlobal: true }),
    TypeOrmModule.forRoot({
      type: 'postgres',
      host: process.env.DATABASE_HOSTNAME,
      port: Number(process.env.DATABASE_PORT),
      username: process.env.DATABASE_USER,
      password: process.env.DATABASE_PASSWORD,
      database: process.env.DATABASE_NAME,
      synchronize: false,
      migrationsRun: true,
      entities: [__dirname + '/../**/*.{entity,repository}.{js,ts}'],
    }),
    HealthModule,
    UsersModule,
    CredentialsModule,
    MocksModule,
    ConnectionsModule,
    TemplatesModule,
    KeypairChallengeModule,
    CertChallengeModule,
    WebhooksModule,
  ],
  controllers: [AppController],
  providers: [AppService],
})
export class AppModule implements NestModule {
  configure(consumer: MiddlewareConsumer) {
    consumer
      .apply(LogsMiddleware)
      .forRoutes('*')
      .apply(ClerkExpressWithAuth())
      .forRoutes('*')
      .apply(
        (req: WithAuthProp<Request>, res: Response, next: NextFunction) => {
          const userId = req.auth?.userId;
          if (!userId && !req.originalUrl.includes('.well-known'))
            throw new UnauthorizedException();
          next();
        },
      )
      .exclude(
        '.well-known/(.*)',
        'health',
        'v1/mocks',
        'v1/mocks/(.*)',
        'v1/credentials/export',
        'v1/webhooks/(.*)',
      )
      .forRoutes('*');
  }
}
