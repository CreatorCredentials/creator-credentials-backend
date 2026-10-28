import { SendEmailCommand, SESv2Client } from '@aws-sdk/client-sesv2';
import { MailerPort, MailMessage } from '../mailer.port';

export class SesMailer implements MailerPort {
  constructor(
    private readonly client: SESv2Client,
    private readonly from: string,
  ) {}

  async send(message: MailMessage): Promise<void> {
    await this.client.send(
      new SendEmailCommand({
        FromEmailAddress: this.from,
        Destination: { ToAddresses: message.to },
        Content: {
          Simple: {
            Subject: { Data: message.subject },
            Body: {
              Text: { Data: message.text },
              Html: { Data: message.html },
            },
          },
        },
      }),
    );
  }
}
