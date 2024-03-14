import { Credential } from './credential.entity';

export function formatCredential(credential: Credential) {
  return {
    ...credential.credentialObject,
    status: credential.credentialStatus,
    domain: credential.email,
    proof: {
      type: 'JwtProof2020',
      jwt: credential.token,
    },
  };
}
