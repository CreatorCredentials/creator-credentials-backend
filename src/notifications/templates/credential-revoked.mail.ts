import { CredentialType } from 'src/shared/typings/CredentialType';
import { MailContent } from '../mailer.port';
import { credentialTypeLabel } from './credential-type-labels';
import { renderMail } from './mail-layout';

export function credentialRevokedMail(
  input: {
    issuerName: string;
    credentialType: CredentialType;
    reason: string | null;
  },
  appBaseUrl: string,
): MailContent {
  const label = credentialTypeLabel(input.credentialType);
  return renderMail(
    {
      subject: `Your ${label} credential was revoked by ${input.issuerName}`,
      lines: [
        `${input.issuerName} revoked your ${label} credential on Creator Credentials.`,
        input.reason ? `Reason: ${input.reason}` : 'No reason was given.',
        'The credential stays listed in your account as revoked.',
      ],
      link: { label: 'Open your credentials', path: '/creator/credentials' },
    },
    appBaseUrl,
  );
}
