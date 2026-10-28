import { CredentialType } from 'src/shared/typings/CredentialType';

const CREDENTIAL_TYPE_LABELS: Record<CredentialType, string> = {
  [CredentialType.EMail]: 'E-Mail',
  [CredentialType.Wallet]: 'Wallet',
  [CredentialType.Member]: 'Member',
  [CredentialType.DataSupplier]: 'Open Future Data Supplier',
  [CredentialType.LicciumDataSupplier]: 'Liccium Data Supplier',
  [CredentialType.Student]: 'Student',
  [CredentialType.Domain]: 'Domain',
  [CredentialType.DidWeb]: 'DID Web',
  [CredentialType.Connect]: 'Connect',
  [CredentialType.ExternalKeypairVerification]: 'Keypair Verification',
  [CredentialType.Creator]: 'Verified Creator',
};

export function credentialTypeLabel(type: CredentialType): string {
  return CREDENTIAL_TYPE_LABELS[type] ?? type;
}
