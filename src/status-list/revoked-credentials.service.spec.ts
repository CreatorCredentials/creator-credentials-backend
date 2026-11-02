import { Test, TestingModule } from '@nestjs/testing';
import { getRepositoryToken } from '@nestjs/typeorm';
import { IsNull } from 'typeorm';
import { Credential } from 'src/credentials/credential.entity';
import { CredentialVerificationStatus } from 'src/shared/typings/CredentialVerificationStatus';
import {
  leafCertificateOf,
  parseCompactJws,
  verifyJwsSignature,
} from 'src/verification/jws';
import { RevokedCredentialsService } from './revoked-credentials.service';
import {
  EphemeralPlatformSigner,
  PLATFORM_DID,
  installEphemeralPlatformSigner,
} from '../../test/support/platform-signer';

const API_BASE_URL = 'https://api.example.org';
const REVOKED_AT = new Date('2026-11-01T10:00:00.000Z');

function revokedCredential(overrides: Partial<Credential> = {}): Credential {
  return {
    id: 1,
    credentialObject: {
      id: 'urn:uuid:11111111-1111-1111-1111-111111111111',
      issuer: 'did:web:issuer.example',
    },
    revokedAt: REVOKED_AT,
    ...overrides,
  } as Credential;
}

describe('RevokedCredentialsService', () => {
  const repository = { find: jest.fn() };
  let service: RevokedCredentialsService;
  let platformSigner: EphemeralPlatformSigner;

  beforeAll(async () => {
    process.env.API_BASE_URL = API_BASE_URL;
    platformSigner = await installEphemeralPlatformSigner();
  });

  afterAll(() => {
    delete process.env.API_BASE_URL;
    platformSigner.cleanup();
  });

  beforeEach(async () => {
    jest.resetAllMocks();
    repository.find.mockResolvedValue([revokedCredential()]);
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        RevokedCredentialsService,
        { provide: getRepositoryToken(Credential), useValue: repository },
      ],
    }).compile();
    service = module.get(RevokedCredentialsService);
  });

  it('selects only revoked credentials without a status list index', async () => {
    await service.getRegistry();

    expect(repository.find).toHaveBeenCalledWith(
      expect.objectContaining({
        where: {
          credentialStatus: CredentialVerificationStatus.Revoked,
          statusListIndex: IsNull(),
        },
      }),
    );
  });

  it('names itself, the platform and the status list that covers the other credentials', async () => {
    const { registry } = await service.getRegistry();

    expect(registry).toEqual(
      expect.objectContaining({
        id: `${API_BASE_URL}/v1/revoked-credentials`,
        type: 'RevokedCredentialsRegistry',
        issuer: PLATFORM_DID,
        statusListCredential: `${API_BASE_URL}/v1/status-lists/1`,
        generatedAt: expect.any(String),
        description: expect.stringContaining('credentialStatus'),
      }),
    );
  });

  it('lists each revoked credential by its id with issuer and revocation time', async () => {
    const { registry } = await service.getRegistry();

    expect(registry.revokedCredentials).toEqual([
      {
        id: 'urn:uuid:11111111-1111-1111-1111-111111111111',
        issuer: 'did:web:issuer.example',
        revokedAt: REVOKED_AT.toISOString(),
      },
    ]);
  });

  it('reads an issuer given as an object and tolerates a missing revocation time', async () => {
    repository.find.mockResolvedValue([
      revokedCredential({
        credentialObject: {
          id: 'urn:uuid:2',
          issuer: { id: 'did:web:other.example', name: 'Other' },
        },
        revokedAt: undefined,
      }),
    ]);

    const { registry } = await service.getRegistry();

    expect(registry.revokedCredentials).toEqual([
      { id: 'urn:uuid:2', issuer: 'did:web:other.example', revokedAt: null },
    ]);
  });

  it('leaves out a credential whose object carries no id', async () => {
    repository.find.mockResolvedValue([
      revokedCredential({ credentialObject: { issuer: 'did:web:x' } }),
      revokedCredential({ id: 2, credentialObject: { id: 'urn:uuid:kept' } }),
    ]);

    const { registry } = await service.getRegistry();

    expect(
      (registry.revokedCredentials as { id: string }[]).map((r) => r.id),
    ).toEqual(['urn:uuid:kept']);
  });

  it('signs the document with the platform certificate and embeds the JWS as proof', async () => {
    const { registry, jwt } = await service.getRegistry();
    const jws = parseCompactJws(jwt);

    expect(registry.proof).toEqual({ type: 'JwtProof2020', jwt });
    expect(verifyJwsSignature(jws, leafCertificateOf(jws.header))).toBe(true);
    expect(jws.payload.revokedCredentials).toEqual(registry.revokedCredentials);
    expect(jws.payload.issuer).toBe(PLATFORM_DID);
  });
});
