import * as crypto from 'crypto';
import { of } from 'rxjs';
import { BadRequestException } from '@nestjs/common';
import { HttpService } from '@nestjs/axios';
import { Crypto } from '@peculiar/webcrypto';
import { X509CertificateGenerator, cryptoProvider } from '@peculiar/x509';
import { signJWTWithX5c } from 'src/credentials/credentials.helpers';
import { encodeBitstring } from 'src/status-list/bitstring';
import { StatusListService } from 'src/status-list/status-list.service';
import { VerificationService } from './verification.service';
import {
  EphemeralPlatformSigner,
  PLATFORM_DID,
  installEphemeralPlatformSigner,
} from '../../test/support/platform-signer';

const LOCAL_LIST_URL = 'https://api.example.org/v1/status-lists/1';
const REMOTE_LIST_URL = 'https://other.example/status/7';
const INDEX = 12;
const DAY_MS = 24 * 60 * 60 * 1000;

const webcrypto = new Crypto();
cryptoProvider.set(webcrypto);

const PUBLIC_ADDRESS = '93.184.216.34';
const dnsLookup = jest.fn();
jest.mock('dns/promises', () => ({
  lookup: (...args: unknown[]) => dnsLookup(...args),
}));

/** A signed BitstringStatusListCredential as a remote issuer would serve it. */
async function signedStatusList(
  setIndices: number[],
  overrides: Record<string, unknown> = {},
  subjectOverrides: Record<string, unknown> = {},
): Promise<string> {
  const now = Date.now();
  return signJWTWithX5c(
    {
      '@context': ['https://www.w3.org/ns/credentials/v2'],
      id: REMOTE_LIST_URL,
      type: ['VerifiableCredential', 'BitstringStatusListCredential'],
      issuer: 'did:web:other.example',
      validFrom: new Date(now - DAY_MS).toISOString(),
      validUntil: new Date(now + DAY_MS).toISOString(),
      credentialSubject: {
        id: `${REMOTE_LIST_URL}#list`,
        type: 'BitstringStatusList',
        statusPurpose: 'revocation',
        encodedList: encodeBitstring(setIndices),
        ...subjectOverrides,
      },
      ...overrides,
    },
    undefined,
    { typ: 'vc+jwt' },
  );
}

function remoteResponse(data: unknown) {
  httpService.get.mockReturnValue(of({ data }));
}

function remoteCredential(entryOverrides: Record<string, unknown> = {}) {
  return buildCredential({
    credentialStatus: { ...statusEntry(REMOTE_LIST_URL), ...entryOverrides },
  });
}

const httpService = { get: jest.fn() };

function statusEntry(statusListCredential: string, index = INDEX) {
  return {
    id: `${statusListCredential}#${index}`,
    type: 'BitstringStatusListEntry',
    statusPurpose: 'revocation',
    statusListIndex: String(index),
    statusListCredential,
  };
}

function buildCredential(overrides: Record<string, unknown> = {}) {
  const now = Date.now();
  return {
    '@context': ['https://www.w3.org/ns/credentials/v2'],
    id: 'urn:uuid:11111111-1111-1111-1111-111111111111',
    type: ['VerifiableCredential', 'VerifiableAttestation', 'VerifiableEmail'],
    issuer: PLATFORM_DID,
    validFrom: new Date(now - DAY_MS).toISOString(),
    validUntil: new Date(now + DAY_MS).toISOString(),
    credentialSubject: { id: 'did:key:zAlice', email: 'alice@example.org' },
    credentialStatus: statusEntry(LOCAL_LIST_URL),
    ...overrides,
  };
}

function tamper(jwt: string): string {
  const [header, payload, signature] = jwt.split('.');
  const claims = JSON.parse(Buffer.from(payload, 'base64url').toString());
  claims.credentialSubject.email = 'mallory@example.org';
  const forged = Buffer.from(JSON.stringify(claims)).toString('base64url');
  return `${header}.${forged}.${signature}`;
}

/** A self-signed P-256 certificate and the Node key object that signs for it. */
async function generateEcSigner() {
  const algorithm = { name: 'ECDSA', namedCurve: 'P-256', hash: 'SHA-256' };
  const keys = await webcrypto.subtle.generateKey(algorithm, true, [
    'sign',
    'verify',
  ]);
  const certificate = await X509CertificateGenerator.createSelfSigned({
    serialNumber: '02',
    name: 'CN=issuer.example',
    notBefore: new Date(Date.now() - DAY_MS),
    notAfter: new Date(Date.now() + DAY_MS),
    signingAlgorithm: algorithm,
    keys,
  });
  const pkcs8 = await webcrypto.subtle.exportKey('pkcs8', keys.privateKey);
  return {
    certificateBase64: certificate.toString('base64'),
    privateKey: crypto.createPrivateKey({
      key: Buffer.from(pkcs8),
      format: 'der',
      type: 'pkcs8',
    }),
  };
}

function signEs256(
  payload: object,
  signer: { certificateBase64: string; privateKey: crypto.KeyObject },
  dsaEncoding: 'ieee-p1363' | 'der',
): string {
  const header = { alg: 'ES256', typ: 'JWT', x5c: [signer.certificateBase64] };
  const signingInput = [header, payload]
    .map((part) => Buffer.from(JSON.stringify(part)).toString('base64url'))
    .join('.');
  const signature = crypto.sign('sha256', Buffer.from(signingInput), {
    key: signer.privateKey,
    dsaEncoding,
  });
  return `${signingInput}.${signature.toString('base64url')}`;
}

describe('VerificationService', () => {
  const statusList = { isLocalListUrl: jest.fn(), isRevoked: jest.fn() };
  let service: VerificationService;
  let platformSigner: EphemeralPlatformSigner;

  beforeAll(async () => {
    platformSigner = await installEphemeralPlatformSigner();
  });

  afterAll(() => {
    platformSigner.cleanup();
  });

  beforeEach(() => {
    jest.resetAllMocks();
    statusList.isLocalListUrl.mockImplementation(
      (url: string) => url === LOCAL_LIST_URL,
    );
    statusList.isRevoked.mockResolvedValue(false);
    dnsLookup.mockResolvedValue([{ address: PUBLIC_ADDRESS, family: 4 }]);
    service = new VerificationService(
      statusList as unknown as StatusListService,
      httpService as unknown as HttpService,
    );
  });

  it('passes a platform-signed credential that is in time and not revoked', async () => {
    const credential = buildCredential();
    const jwt = await signJWTWithX5c(credential);

    const result = await service.verify({ jwt });

    expect(result.valid).toBe(true);
    expect(result.checks.signature).toEqual({
      valid: true,
      issuerDid: PLATFORM_DID,
      certificateSubject: expect.stringContaining(`CN=${PLATFORM_DID}`),
    });
    expect(result.checks.validity).toEqual({
      valid: true,
      validFrom: credential.validFrom,
      validUntil: credential.validUntil,
    });
    expect(result.checks.revocation).toEqual({
      status: 'valid',
      checkedAt: expect.any(String),
    });
    expect(result.credential).toEqual(credential);
    expect(statusList.isRevoked).toHaveBeenCalledWith(INDEX);
  });

  it('accepts the credential object with its proof and compares it to the payload', async () => {
    const credential = buildCredential();
    const jwt = await signJWTWithX5c(credential);

    const result = await service.verify({
      credential: { ...credential, proof: { type: 'JwtProof2020', jwt } },
    });

    expect(result.valid).toBe(true);
    expect(result.credential).not.toHaveProperty('proof');
  });

  it('fails the signature when the given credential differs from the signed payload', async () => {
    const credential = buildCredential();
    const jwt = await signJWTWithX5c(credential);

    const result = await service.verify({
      jwt,
      credential: {
        ...credential,
        credentialSubject: { ...credential.credentialSubject, email: 'x@y.z' },
      },
    });

    expect(result.checks.signature.valid).toBe(false);
    expect(result.valid).toBe(false);
  });

  it('fails the signature of a tampered token and keeps the other checks', async () => {
    const jwt = tamper(await signJWTWithX5c(buildCredential()));

    const result = await service.verify({ jwt });

    expect(result.valid).toBe(false);
    expect(result.checks.signature.valid).toBe(false);
    expect(result.checks.signature.certificateSubject).toContain(PLATFORM_DID);
    expect(result.checks.validity.valid).toBe(true);
  });

  it('fails validity for an expired credential while the signature holds', async () => {
    const jwt = await signJWTWithX5c(
      buildCredential({
        validFrom: new Date(Date.now() - 2 * DAY_MS).toISOString(),
        validUntil: new Date(Date.now() - DAY_MS).toISOString(),
      }),
    );

    const result = await service.verify({ jwt });

    expect(result.valid).toBe(false);
    expect(result.checks.signature.valid).toBe(true);
    expect(result.checks.validity.valid).toBe(false);
  });

  it('reports a revoked credential as invalid with a valid signature', async () => {
    statusList.isRevoked.mockResolvedValue(true);
    const jwt = await signJWTWithX5c(buildCredential());

    const result = await service.verify({ jwt });

    expect(result.valid).toBe(false);
    expect(result.checks.signature.valid).toBe(true);
    expect(result.checks.revocation.status).toBe('revoked');
  });

  it('reports revocation as unknown for a credential without status entry', async () => {
    const jwt = await signJWTWithX5c(
      buildCredential({ credentialStatus: undefined }),
    );

    const result = await service.verify({ jwt });

    expect(result.valid).toBe(true);
    expect(result.checks.revocation.status).toBe('unknown');
    expect(statusList.isRevoked).not.toHaveBeenCalled();
  });

  it('rejects the credential when the status list cannot be read', async () => {
    statusList.isRevoked.mockRejectedValue(new Error('database down'));
    const jwt = await signJWTWithX5c(buildCredential());

    const result = await service.verify({ jwt });

    expect(result.checks.revocation).toMatchObject({
      status: 'error',
      reason: 'STATUS_RETRIEVAL_ERROR',
    });
    expect(result.valid).toBe(false);
  });

  describe('foreign status lists', () => {
    it('fetches the list as a JWS, verifies it and reads the bit', async () => {
      remoteResponse(await signedStatusList([INDEX]));
      const jwt = await signJWTWithX5c(remoteCredential());

      const result = await service.verify({ jwt });

      expect(httpService.get).toHaveBeenCalledWith(
        REMOTE_LIST_URL,
        expect.objectContaining({
          headers: { Accept: 'application/vc+jwt, application/json' },
          maxRedirects: 0,
        }),
      );
      expect(result.checks.revocation.status).toBe('revoked');
      expect(statusList.isRevoked).not.toHaveBeenCalled();
    });

    it('accepts the JSON form that carries the JWS in proof.jwt', async () => {
      const list = await signedStatusList([]);
      remoteResponse({ proof: { type: 'JwtProof2020', jwt: list } });
      const jwt = await signJWTWithX5c(remoteCredential());

      const result = await service.verify({ jwt });

      expect(result.checks.revocation.status).toBe('valid');
      expect(result.valid).toBe(true);
    });

    it('rejects a list whose signature does not verify', async () => {
      const [header, , signature] = (await signedStatusList([INDEX])).split(
        '.',
      );
      const [, forgedPayload] = (await signedStatusList([])).split('.');
      remoteResponse(`${header}.${forgedPayload}.${signature}`);
      const jwt = await signJWTWithX5c(remoteCredential());

      const result = await service.verify({ jwt });

      expect(result.checks.revocation).toMatchObject({
        status: 'error',
        reason: 'STATUS_VERIFICATION_ERROR',
      });
      expect(result.valid).toBe(false);
    });

    it('rejects a list that is not secured as a JWS at all', async () => {
      remoteResponse({
        type: ['VerifiableCredential', 'BitstringStatusListCredential'],
        credentialSubject: { encodedList: encodeBitstring([]) },
      });
      const jwt = await signJWTWithX5c(remoteCredential());

      const result = await service.verify({ jwt });

      expect(result.checks.revocation.reason).toBe('STATUS_VERIFICATION_ERROR');
    });

    it('rejects a list whose purpose does not include revocation', async () => {
      remoteResponse(
        await signedStatusList([], {}, { statusPurpose: 'suspension' }),
      );
      const jwt = await signJWTWithX5c(remoteCredential());

      const result = await service.verify({ jwt });

      expect(result.checks.revocation.reason).toBe('STATUS_VERIFICATION_ERROR');
    });

    it('accepts a list that serves several purposes', async () => {
      remoteResponse(
        await signedStatusList(
          [],
          {},
          {
            statusPurpose: ['suspension', 'revocation'],
          },
        ),
      );
      const jwt = await signJWTWithX5c(remoteCredential());

      const result = await service.verify({ jwt });

      expect(result.checks.revocation.status).toBe('valid');
    });

    it('rejects a list shorter than the minimum of 131 072 entries', async () => {
      remoteResponse(
        await signedStatusList([], {}, { encodedList: encodeBitstring([], 8) }),
      );
      const jwt = await signJWTWithX5c(remoteCredential());

      const result = await service.verify({ jwt });

      expect(result.checks.revocation.reason).toBe('STATUS_LIST_LENGTH_ERROR');
    });

    it('reports an index outside the list as a range error', async () => {
      remoteResponse(await signedStatusList([]));
      const jwt = await signJWTWithX5c(
        remoteCredential({ statusListIndex: '131072' }),
      );

      const result = await service.verify({ jwt });

      expect(result.checks.revocation.reason).toBe('RANGE_ERROR');
    });

    it('rejects a list outside its validity window', async () => {
      remoteResponse(
        await signedStatusList([], {
          validUntil: new Date(Date.now() - DAY_MS).toISOString(),
        }),
      );
      const jwt = await signJWTWithX5c(remoteCredential());

      const result = await service.verify({ jwt });

      expect(result.checks.revocation.reason).toBe('STATUS_VERIFICATION_ERROR');
    });

    it('refuses to fetch lists that are not public https URLs', async () => {
      const jwt = await signJWTWithX5c(
        remoteCredential({ statusListCredential: 'http://other.example/l' }),
      );

      const result = await service.verify({ jwt });

      expect(result.checks.revocation.reason).toBe('STATUS_RETRIEVAL_ERROR');
      expect(httpService.get).not.toHaveBeenCalled();
    });

    it('refuses to fetch lists from private network addresses', async () => {
      dnsLookup.mockResolvedValue([{ address: '10.0.0.5', family: 4 }]);
      const jwt = await signJWTWithX5c(remoteCredential());

      const result = await service.verify({ jwt });

      expect(result.checks.revocation.reason).toBe('STATUS_RETRIEVAL_ERROR');
      expect(httpService.get).not.toHaveBeenCalled();
    });
  });

  describe('malformed status entries', () => {
    it.each([
      ['a numeric statusListIndex', { statusListIndex: 12 }],
      ['an index with whitespace', { statusListIndex: ' 12 ' }],
      ['an index in scientific notation', { statusListIndex: '1e3' }],
      ['a non-string statusListCredential', { statusListCredential: 7 }],
    ])('rejects %s as malformed', async (_, overrides) => {
      const jwt = await signJWTWithX5c(remoteCredential(overrides));

      const result = await service.verify({ jwt });

      expect(result.checks.revocation).toMatchObject({
        status: 'error',
        reason: 'MALFORMED_VALUE_ERROR',
      });
      expect(result.valid).toBe(false);
    });

    it('does not read multi-bit statuses it cannot interpret', async () => {
      const jwt = await signJWTWithX5c(remoteCredential({ statusSize: 2 }));

      const result = await service.verify({ jwt });

      expect(result.checks.revocation.reason).toBe('UNSUPPORTED_STATUS_SIZE');
    });
  });

  it('verifies ES256 tokens in raw and in DER signature form', async () => {
    const signer = await generateEcSigner();
    const credential = buildCredential({ issuer: 'did:web:issuer.example' });

    const raw = await service.verify({
      jwt: signEs256(credential, signer, 'ieee-p1363'),
    });
    const der = await service.verify({
      jwt: signEs256(credential, signer, 'der'),
    });

    expect(raw.checks.signature).toMatchObject({
      valid: true,
      issuerDid: 'did:web:issuer.example',
      certificateSubject: 'CN=issuer.example',
    });
    expect(der.checks.signature.valid).toBe(true);
  });

  it('fails the signature of a token without x5c certificate', async () => {
    const credential = buildCredential();
    const [, payload] = (await signJWTWithX5c(credential)).split('.');
    const header = Buffer.from(JSON.stringify({ alg: 'RS256' })).toString(
      'base64url',
    );

    const result = await service.verify({ jwt: `${header}.${payload}.c2ln` });

    expect(result.checks.signature).toEqual({
      valid: false,
      issuerDid: PLATFORM_DID,
      certificateSubject: null,
    });
  });

  it.each([
    ['an empty body', {}],
    ['a non-string jwt', { jwt: 42 }],
    ['a two-part token', { jwt: 'a.b' }],
    [
      'a token whose payload is not JSON',
      { jwt: 'eyJhbGciOiJSUzI1NiJ9.bm90LWpzb24.c2ln' },
    ],
    ['a credential without proof.jwt', { credential: { id: 'urn:uuid:x' } }],
  ])('answers 400 for %s', async (_case, body) => {
    await expect(service.verify(body)).rejects.toThrow(BadRequestException);
  });
});
