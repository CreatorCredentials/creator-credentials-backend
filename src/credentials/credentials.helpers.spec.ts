import { ClerkRole, User } from 'src/users/user.entity';
import { buildCreatorCredentialObject } from './credentials.helpers';

const CREATOR_SCHEMA_ID =
  'https://raw.githubusercontent.com/CreatorCredentials/specifications/main/json-schema/verification-credentials/creator/schema.json';

describe('buildCreatorCredentialObject', () => {
  const creator = Object.assign(new User(), {
    id: 20,
    clerkRole: ClerkRole.Creator,
    didKey: 'did:key:zAlice',
    activeDidKeySource: 'platform',
  });

  it('describes a platform-issued VerifiableCreator for the creator did:key', () => {
    const credentialObject = buildCreatorCredentialObject(
      creator,
      'liccium.com',
    );

    expect(credentialObject).toMatchObject({
      type: [
        'VerifiableCredential',
        'VerifiableAttestation',
        'VerifiableCreator',
      ],
      issuer: 'did:web:liccium.com',
      credentialSubject: { id: 'did:key:zAlice', verifiedBy: 'liccium.com' },
      credentialSchema: [{ id: CREATOR_SCHEMA_ID, type: 'JsonSchema' }],
      termsOfUse: {
        type: 'PresentationPolicy',
        confidentialityLevel: 'public',
        pii: 'none',
      },
    });
    expect(credentialObject.id).toMatch(/^urn:uuid:/);
  });
});
