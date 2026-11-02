import { Controller, Get, Header, Headers, Query, Res } from '@nestjs/common';
import { type Response } from 'express';
import { wantsJwt } from './jwt-format';
import { RevokedCredentialsService } from './revoked-credentials.service';
import {
  JWT_MEDIA_TYPE,
  STATUS_LIST_CACHE_TTL_MS,
} from './status-list.constants';

const MAX_AGE_SECONDS = STATUS_LIST_CACHE_TTL_MS / 1000;

/** Public: the revoked credentials that carry no status entry; no Clerk session is required. */
@Controller('revoked-credentials')
export class RevokedCredentialsController {
  constructor(private readonly revokedCredentials: RevokedCredentialsService) {}

  @Get()
  @Header('Cache-Control', `public, max-age=${MAX_AGE_SECONDS}`)
  async getRegistry(
    @Query('format') format: string | undefined,
    @Headers('accept') accept: string | undefined,
    @Res({ passthrough: true }) response: Response,
  ) {
    const registry = await this.revokedCredentials.getRegistry();
    if (wantsJwt(format, accept, JWT_MEDIA_TYPE)) {
      response.type(JWT_MEDIA_TYPE);
      return registry.jwt;
    }
    return registry.registry;
  }
}
