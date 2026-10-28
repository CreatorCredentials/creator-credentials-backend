import { User } from './user.entity';
import { CredentialType } from 'src/shared/typings/CredentialType';
import { CredentialVerificationStatus } from 'src/shared/typings/CredentialVerificationStatus';

/**
 * The e-mail address a user has proven in the app: their SUCCESS EMAIL
 * credential. Expects `user.credentials` to be loaded.
 */
export function findVerifiedEmail(user: User): string | undefined {
  return (user.credentials ?? []).find(
    (credential) =>
      credential.credentialType === CredentialType.EMail &&
      credential.credentialStatus === CredentialVerificationStatus.Success,
  )?.email;
}
