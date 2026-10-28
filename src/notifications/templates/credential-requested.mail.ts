import { CredentialType } from 'src/shared/typings/CredentialType';
import { MailContent } from '../mailer.port';
import { credentialTypeLabel } from './credential-type-labels';
import { renderMail } from './mail-layout';

export function credentialRequestedMail(
  input: { creatorName: string; credentialType: CredentialType },
  appBaseUrl: string,
): MailContent {
  const label = credentialTypeLabel(input.credentialType);
  return renderMail(
    {
      subject: `New ${label} credential request from ${input.creatorName}`,
      lines: [
        `${input.creatorName} requested a ${label} credential from you on Creator Credentials.`,
        'Review the request to accept or reject it.',
      ],
      link: {
        label: 'Review credential requests',
        path: '/issuer/credentials/requested',
      },
    },
    appBaseUrl,
  );
}
