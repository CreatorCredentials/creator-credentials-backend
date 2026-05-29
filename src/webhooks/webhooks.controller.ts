import {
  Controller,
  Post,
  Headers,
  Req,
  HttpCode,
  BadRequestException,
  Logger,
} from '@nestjs/common';
import { Request } from 'express';
import { Webhook } from 'svix';
import { WebhooksService } from './webhooks.service';

interface RawBodyRequest extends Request {
  rawBody?: Buffer;
}

@Controller('webhooks')
export class WebhooksController {
  private readonly logger = new Logger(WebhooksController.name);

  constructor(private readonly webhooksService: WebhooksService) {}

  @Post('clerk')
  @HttpCode(200)
  async handleClerkWebhook(
    @Headers('svix-id') svixId: string,
    @Headers('svix-timestamp') svixTimestamp: string,
    @Headers('svix-signature') svixSignature: string,
    @Req() req: RawBodyRequest,
  ) {
    const secret = process.env.CLERK_WEBHOOK_SIGNING_SECRET;
    if (!secret) {
      this.logger.error('CLERK_WEBHOOK_SIGNING_SECRET is not configured');
      throw new BadRequestException('Webhook signing secret not configured');
    }

    const wh = new Webhook(secret);
    let event: { type: string; data: any };

    try {
      event = wh.verify(req.rawBody as unknown as string, {
        'svix-id': svixId,
        'svix-timestamp': svixTimestamp,
        'svix-signature': svixSignature,
      }) as { type: string; data: any };
    } catch (err) {
      this.logger.warn(`Clerk webhook signature verification failed: ${err.message}`);
      throw new BadRequestException('Invalid webhook signature');
    }

    await this.webhooksService.handleEvent(event);
    return { received: true };
  }
}
