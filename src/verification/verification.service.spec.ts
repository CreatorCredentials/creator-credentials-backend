import { readFileSync } from 'fs';
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

const PLATFORM_PRIVATE_KEY_PATH = 'certificates/LICCIUM_priv.pem';
const PLATFORM_DID = 'did:web:liccium.com';
const LOCAL_LIST_URL = 'https://api.example.org/v1/status-lists/1';
const REMOTE_LIST_URL = 'https://other.example/status/7';
const INDEX = 12;
const DAY_MS = 24 * 60 * 60 * 1000;

const webcrypto = new Crypto();
cryptoProvider.set(webcrypto);

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
  const httpService = { get: jest.fn() };
  let service: VerificationService;

  beforeAll(() => {
    process.env.HALCOM_CERT_PRIVATE_KEY = readFileSync(
      PLATFORM_PRIVATE_KEY_PATH,
      'utf8',
    );
  });

  afterAll(() => {
    delete process.env.HALCOM_CERT_PRIVATE_KEY;
  });

  beforeEach(() => {
    jest.resetAllMocks();
    statusList.isLocalListUrl.mockImplementation(
      (url: string) => url === LOCAL_LIST_URL,
    );
    statusList.isRevoked.mockResolvedValue(false);
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

  it('reports revocation as unknown when the status list cannot be read', async () => {
    statusList.isRevoked.mockRejectedValue(new Error('database down'));
    const jwt = await signJWTWithX5c(buildCredential());

    const result = await service.verify({ jwt });

    expect(result.checks.revocation.status).toBe('unknown');
    expect(result.valid).toBe(true);
  });

  it('fetches a foreign status list over HTTP and reads the bit', async () => {
    httpService.get.mockReturnValue(
      of({
        data: {
          credentialSubject: { encodedList: encodeBitstring([INDEX]) },
        },
      }),
    );
    const jwt = await signJWTWithX5c(
      buildCredential({ credentialStatus: statusEntry(REMOTE_LIST_URL) }),
    );

    const result = await service.verify({ jwt });

    expect(httpService.get).toHaveBeenCalledWith(
      REMOTE_LIST_URL,
      expect.objectContaining({ headers: { Accept: 'application/json' } }),
    );
    expect(result.checks.revocation.status).toBe('revoked');
    expect(statusList.isRevoked).not.toHaveBeenCalled();
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
