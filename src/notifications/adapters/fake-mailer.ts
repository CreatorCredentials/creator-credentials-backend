import { MailerPort, MailMessage } from '../mailer.port';

/** Test double that keeps every message it was asked to send. */
export class FakeMailer implements MailerPort {
  readonly messages: MailMessage[] = [];

  async send(message: MailMessage): Promise<void> {
    this.messages.push(message);
  }
}
