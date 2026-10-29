import { CredentialType } from 'src/shared/typings/CredentialType';
import { MailContent } from '../mailer.port';
import { credentialTypeLabel } from './credential-type-labels';
import { renderMail } from './mail-layout';

/** Issuer-facing: a platform administrator revoked a credential this issuer issued. */
export function issuedCredentialRevokedMail(
  input: {
    creatorName: string;
    credentialType: CredentialType;
    reason: string | null;
  },
  appBaseUrl: string,
): MailContent {
  const label = credentialTypeLabel(input.credentialType);
  return renderMail(
    {
      subject: `The ${label} credential you issued to ${input.creatorName} was revoked`,
      lines: [
        `A Creator Credentials administrator revoked the ${label} credential you issued to ${input.creatorName}.`,
        input.reason ? `Reason: ${input.reason}` : 'No reason was given.',
        'The credential is listed as revoked in your issued credentials.',
      ],
      link: { label: 'Open issued credentials', path: '/issuer/credentials' },
    },
    appBaseUrl,
  );
}
