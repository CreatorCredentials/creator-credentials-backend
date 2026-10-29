import { CredentialType } from 'src/shared/typings/CredentialType';
import { MailContent } from '../mailer.port';
import { credentialTypeLabel } from './credential-type-labels';
import { renderMail } from './mail-layout';

const PLATFORM_NAME = 'the Creator Credentials platform';

/** Creator-facing: who revoked and why. `issuerName` is null for a self-issued credential. */
export function credentialRevokedMail(
  input: {
    issuerName: string | null;
    credentialType: CredentialType;
    reason: string | null;
    revokedByPlatform: boolean;
  },
  appBaseUrl: string,
): MailContent {
  const label = credentialTypeLabel(input.credentialType);
  const revoker = input.revokedByPlatform
    ? PLATFORM_NAME
    : input.issuerName ?? PLATFORM_NAME;
  const issuedBy =
    input.revokedByPlatform && input.issuerName
      ? ` issued by ${input.issuerName}`
      : '';
  return renderMail(
    {
      subject: `Your ${label} credential was revoked by ${revoker}`,
      lines: [
        `${capitalize(
          revoker,
        )} revoked your ${label} credential${issuedBy} on Creator Credentials.`,
        input.reason ? `Reason: ${input.reason}` : 'No reason was given.',
        'The credential stays listed in your account as revoked.',
      ],
      link: { label: 'Open your credentials', path: '/creator/credentials' },
    },
    appBaseUrl,
  );
}

function capitalize(text: string): string {
  return text.charAt(0).toUpperCase() + text.slice(1);
}
