import { ClerkRole, User } from 'src/users/user.entity';
import { buildCreatorCredentialObject } from './credentials.helpers';
import {
  EphemeralPlatformSigner,
  PLATFORM_DID,
  installEphemeralPlatformSigner,
} from '../../test/support/platform-signer';

const CREATOR_SCHEMA_ID =
  'https://raw.githubusercontent.com/CreatorCredentials/specifications/main/json-schema/verification-credentials/creator/schema.json';
const SUBJECT_DID_KEY = 'did:key:zAliceExternal';

const pemOf = (certificateBase64: string) =>
  `-----BEGIN CERTIFICATE-----\n${certificateBase64}\n-----END CERTIFICATE-----\n`;

describe('buildCreatorCredentialObject', () => {
  let signer: EphemeralPlatformSigner;
  let issuer: User;

  beforeAll(async () => {
    signer = await installEphemeralPlatformSigner();
    issuer = Object.assign(new User(), {
      id: 10,
      clerkRole: ClerkRole.Issuer,
      domain: 'issuer.example',
      externalCertPem: pemOf(signer.certificateBase64),
    });
  });

  afterAll(() => signer.cleanup());

  it('describes a VerifiableCreator issued by the certificate holder for the proven did:key', () => {
    const credentialObject = buildCreatorCredentialObject(
      SUBJECT_DID_KEY,
      issuer,
    );

    expect(credentialObject).toMatchObject({
      type: [
        'VerifiableCredential',
        'VerifiableAttestation',
        'VerifiableCreator',
      ],
      issuer: PLATFORM_DID,
      credentialSubject: { id: SUBJECT_DID_KEY, verifiedBy: 'issuer.example' },
      credentialSchema: [{ id: CREATOR_SCHEMA_ID, type: 'JsonSchema' }],
      termsOfUse: {
        type: 'PresentationPolicy',
        confidentialityLevel: 'public',
        pii: 'none',
      },
    });
    expect(credentialObject.id).toMatch(/^urn:uuid:/);
  });

  it('names the certificate host as verifier when the issuer has no domain', () => {
    const certOnlyIssuer = Object.assign(new User(), {
      ...issuer,
      domain: null,
    });

    const credentialObject = buildCreatorCredentialObject(
      SUBJECT_DID_KEY,
      certOnlyIssuer,
    );

    expect(credentialObject.credentialSubject.verifiedBy).toBe(
      PLATFORM_DID.replace('did:web:', ''),
    );
  });
});
