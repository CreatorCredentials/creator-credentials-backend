import { Logger } from '@nestjs/common';
import { MailerPort, MailMessage } from '../mailer.port';

/** Development default: nothing leaves the process, the message is logged. */
export class LogMailer implements MailerPort {
  private readonly logger = new Logger(LogMailer.name);

  async send(message: MailMessage): Promise<void> {
    this.logger.log(`Mail to ${message.to.join(', ')}: ${message.subject}`);
    this.logger.debug(message.text);
  }
}
