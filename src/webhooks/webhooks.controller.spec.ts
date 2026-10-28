import { BadRequestException, RawBodyRequest } from '@nestjs/common';
import { Request } from 'express';
import { randomBytes } from 'crypto';
import { Webhook } from 'svix';
import { WebhooksController } from './webhooks.controller';
import { WebhooksService } from './webhooks.service';

describe('WebhooksController', () => {
  const secret = `whsec_${randomBytes(24).toString('base64')}`;
  const messageId = 'msg_test';
  const event = { type: 'user.created', data: { id: 'user_123' } };
  const payload = JSON.stringify(event);
  let handleEvent: jest.Mock;
  let controller: WebhooksController;

  beforeEach(() => {
    process.env.CLERK_WEBHOOK_SIGNING_SECRET = secret;
    handleEvent = jest.fn().mockResolvedValue(undefined);
    controller = new WebhooksController({
      handleEvent,
    } as unknown as WebhooksService);
  });

  afterEach(() => {
    delete process.env.CLERK_WEBHOOK_SIGNING_SECRET;
  });

  function signedHeaders(body: string) {
    const timestamp = new Date();
    return {
      signature: new Webhook(secret).sign(messageId, timestamp, body),
      timestamp: Math.floor(timestamp.getTime() / 1000).toString(),
    };
  }

  function requestWithBody(body: string): RawBodyRequest<Request> {
    return { rawBody: Buffer.from(body) } as RawBodyRequest<Request>;
  }

  it('passes a svix-signed event to the service', async () => {
    const { signature, timestamp } = signedHeaders(payload);

    await expect(
      controller.handleClerkWebhook(
        messageId,
        timestamp,
        signature,
        requestWithBody(payload),
      ),
    ).resolves.toEqual({ received: true });

    expect(handleEvent).toHaveBeenCalledWith(event);
  });

  it('rejects a body that does not match the signature', async () => {
    const { signature, timestamp } = signedHeaders(payload);
    const tamperedPayload = JSON.stringify({
      ...event,
      data: { id: 'user_999' },
    });

    await expect(
      controller.handleClerkWebhook(
        messageId,
        timestamp,
        signature,
        requestWithBody(tamperedPayload),
      ),
    ).rejects.toBeInstanceOf(BadRequestException);

    expect(handleEvent).not.toHaveBeenCalled();
  });
});
