import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { SESv2Client } from '@aws-sdk/client-sesv2';
import { clerkClient } from '@clerk/clerk-sdk-node';
import { User } from 'src/users/user.entity';
import { LogMailer } from './adapters/log-mailer';
import { SesMailer } from './adapters/ses-mailer';
import { CLERK_USERS } from './clerk-users.port';
import { MAILER, MailerPort } from './mailer.port';
import { NotificationsService } from './notifications.service';
import { RecipientsService } from './recipients.service';

const SES_PROVIDER = 'ses';

/** `NOTIFY_PROVIDER=ses` sends through SES; anything else only logs. */
function createMailer(): MailerPort {
  if (process.env.NOTIFY_PROVIDER === SES_PROVIDER) {
    return new SesMailer(
      new SESv2Client({ region: process.env.AWS_REGION }),
      process.env.NOTIFY_FROM,
    );
  }
  return new LogMailer();
}

@Module({
  imports: [TypeOrmModule.forFeature([User])],
  providers: [
    NotificationsService,
    RecipientsService,
    { provide: CLERK_USERS, useValue: clerkClient.users },
    { provide: MAILER, useFactory: createMailer },
  ],
})
export class NotificationsModule {}
