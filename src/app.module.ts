import {
  MiddlewareConsumer,
  Module,
  NestModule,
  UnauthorizedException,
} from '@nestjs/common';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { ScheduleModule } from '@nestjs/schedule';
import { ConfigModule } from '@nestjs/config';
import { TypeOrmModule } from '@nestjs/typeorm';
import { HealthModule } from './health/health.module';
import { UsersModule } from './users/users.module';
import LogsMiddleware from './config/logs.middleware';
import { ClerkExpressWithAuth, RequireAuthProp } from '@clerk/clerk-sdk-node';
import { NextFunction } from 'express';
import { CredentialsModule } from './credentials/credentials.module';
import { ServeStaticModule } from '@nestjs/serve-static';
import { join } from 'path';

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
    ServeStaticModule.forRoot({
      rootPath: join(__dirname, '..', 'public'),
      serveRoot: '/',
    }),
  ],
  controllers: [AppController],
  providers: [AppService],
})
export class AppModule implements NestModule {
  configure(consumer: MiddlewareConsumer) {
    consumer
      .apply(LogsMiddleware)
      .forRoutes('*')
      .apply(
        ClerkExpressWithAuth({
          onError: (error) => {
            console.log('ClerkExpressWithAuth error: ', error);
          },
        }),
      )
      .forRoutes('*')
      .apply(
        (req: RequireAuthProp<Request>, res: Response, next: NextFunction) => {
          if (!req.auth.userId) throw new UnauthorizedException();
          next();
        },
      )
      .exclude('.well-known/(.*)')
      .forRoutes('*');
  }
}