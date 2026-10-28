import { MailContent } from '../mailer.port';
import { renderMail } from './mail-layout';

export function connectionRequestedMail(
  input: { creatorName: string },
  appBaseUrl: string,
): MailContent {
  return renderMail(
    {
      subject: `New connection request from ${input.creatorName}`,
      lines: [
        `${input.creatorName} asked to connect with you on Creator Credentials.`,
        'Review the request to accept or reject it.',
      ],
      link: { label: 'Review connection requests', path: '/issuer/creators' },
    },
    appBaseUrl,
  );
}
