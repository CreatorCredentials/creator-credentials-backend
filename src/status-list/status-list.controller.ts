import {
  Controller,
  Get,
  Header,
  Headers,
  NotFoundException,
  Param,
  Query,
  Res,
} from '@nestjs/common';
import { type Response } from 'express';
import { wantsJwt } from './jwt-format';
import { StatusListService } from './status-list.service';
import {
  STATUS_LIST_CACHE_TTL_MS,
  STATUS_LIST_ID,
  VC_JWT_MEDIA_TYPE,
} from './status-list.constants';

const MAX_AGE_SECONDS = STATUS_LIST_CACHE_TTL_MS / 1000;

/** Public: verifiers fetch the revocation list here; no Clerk session is required. */
@Controller('status-lists')
export class StatusListController {
  constructor(private readonly statusList: StatusListService) {}

  @Get(':id')
  @Header('Cache-Control', `public, max-age=${MAX_AGE_SECONDS}`)
  async getStatusList(
    @Param('id') id: string,
    @Query('format') format: string | undefined,
    @Headers('accept') accept: string | undefined,
    @Res({ passthrough: true }) response: Response,
  ) {
    if (id !== String(STATUS_LIST_ID)) {
      throw new NotFoundException('Status list not found.');
    }

    const list = await this.statusList.getCredential();
    if (wantsJwt(format, accept, VC_JWT_MEDIA_TYPE)) {
      response.type(VC_JWT_MEDIA_TYPE);
      return list.jwt;
    }
    return list.credential;
  }
}
