import 'reflect-metadata';
import { ClassSerializerInterceptor, VersioningType } from '@nestjs/common';
import { NestFactory, Reflector } from '@nestjs/core';
import { AppModule } from './app.module';
import getLogLevels from './config/log-levels';
import { existsSync, readFileSync } from 'fs';

/**
 * Local HTTPS is opt-in: set LOCAL_HTTPS_KEY and LOCAL_HTTPS_CERT to PEM
 * file paths. Deployed instances terminate TLS upstream and leave them unset.
 */
function localHttpsOptions() {
  const key = process.env.LOCAL_HTTPS_KEY;
  const cert = process.env.LOCAL_HTTPS_CERT;
  if (!key || !cert || !existsSync(key) || !existsSync(cert)) {
    return undefined;
  }
  return { key: readFileSync(key), cert: readFileSync(cert) };
}

async function bootstrap() {
  const app = await NestFactory.create(AppModule, {
    httpsOptions: localHttpsOptions(),
    logger: getLogLevels(process.env.NODE_ENV === 'production'),
    rawBody: true,
  });

  app.useGlobalInterceptors(new ClassSerializerInterceptor(app.get(Reflector)));

  app.enableCors({
    origin: [
      'https://cc-backend.liccium.network',
      'https://liccium.app',
      'http://localhost:3000',
      'http://localhost:3001',
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
