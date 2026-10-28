import { MailContent } from '../mailer.port';
import { UserCreatedEvent } from '../notification-events';
import { renderMail } from './mail-layout';

export function userCreatedMail(
  event: UserCreatedEvent,
  appBaseUrl: string,
): MailContent {
  const name = event.name || event.email;
  return renderMail(
    {
      subject: `New sign-up on Creator Credentials: ${name} (${event.role})`,
      lines: [
        `A new ${event.role} signed up on Creator Credentials.`,
        `Name: ${name}`,
        `E-mail: ${event.email}`,
      ],
      link: { label: 'Open Creator Credentials', path: '/' },
    },
    appBaseUrl,
  );
}
