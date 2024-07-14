import 'reflect-metadata';
import { VersioningType } from '@nestjs/common';
import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import getLogLevels from './config/log-levels';

async function bootstrap() {
  const app = await NestFactory.create(AppModule, {
    logger: getLogLevels(process.env.NODE_ENV === 'production'),
  });

  app.enableCors({
    origin: [
      'https://cc-backend.liccium.network',
      'https://liccium.app',
      'http://localhost:3105',
      'https://www.creatorcredentials.dev',
      'https://creatorcredentials.dev',
      'https://www.creatorcredentials.app',
      'https://creatorcredentials.app',
    ],
    methods: 'GET,HEAD,PUT,PATCH,POST,DELETE',
  });

  app.enableVersioning({
    type: VersioningType.URI,
    defaultVersion: '1',
  });
  console.log('APP_PORT', process.env.APP_PORT);

  await app.listen(process.env.APP_PORT || 3100);
}
bootstrap();
