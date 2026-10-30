import {
  X509Certificate,
  X509CertificateGenerator,
  cryptoProvider,
  KeyUsageFlags,
  KeyUsagesExtension,
  BasicConstraintsExtension,
} from '@peculiar/x509';
import { Crypto } from '@peculiar/webcrypto';
import { ServiceUnavailableException } from '@nestjs/common';
import { createHash } from 'crypto';
import { TrustStoreService } from '../trust-store/trust-store.service';
import { CertValidatorService } from './cert-validator.service';
import type { TrustAnchor } from '../trust-store/types';

const webcrypto = new Crypto();
cryptoProvider.set(webcrypto);

const RSA_SIG = {
  name: 'RSASSA-PKCS1-v1_5',
  hash: 'SHA-256',
  publicExponent: new Uint8Array([1, 0, 1]),
  modulusLength: 2048,
} as const;

/** Same key shape, but the CA signs with SHA-1, which the validator must reject. */
const RSA_SHA1_SIG = { ...RSA_SIG, hash: 'SHA-1' } as const;

type RsaSigningAlgorithm = typeof RSA_SIG | typeof RSA_SHA1_SIG;

interface IssuedPair {
  cert: X509Certificate;
  privateKey: CryptoKey;
  /** Algorithm bound to `privateKey`; certificates it issues are signed with it. */
  signingAlgorithm: RsaSigningAlgorithm;
}

async function generateCa(
  name = 'CN=Test eIDAS CA, C=EU',
  signingAlgorithm: RsaSigningAlgorithm = RSA_SIG,
): Promise<IssuedPair> {
  const keys = await webcrypto.subtle.generateKey(signingAlgorithm, true, [
    'sign',
    'verify',
  ]);

  const cert = await X509CertificateGenerator.create({
    serialNumber: '01',
    subject: name,
    issuer: name,
    notBefore: new Date(Date.now() - 24 * 3600 * 1000),
    notAfter: new Date(Date.now() + 365 * 24 * 3600 * 1000),
    signingAlgorithm,
    publicKey: keys.publicKey,
    signingKey: keys.privateKey,
    extensions: [
      new BasicConstraintsExtension(true, undefined, true),
      new KeyUsagesExtension(
        KeyUsageFlags.keyCertSign | KeyUsageFlags.cRLSign,
        true,
      ),
    ],
  });

  return { cert, privateKey: keys.privateKey, signingAlgorithm };
}

async function issueLeaf(
  ca: IssuedPair,
  options?: {
    notBefore?: Date;
    notAfter?: Date;
    subject?: string;
    keyUsages?: number;
  },
): Promise<IssuedPair> {
  const keys = await webcrypto.subtle.generateKey(RSA_SIG, true, [
    'sign',
    'verify',
  ]);

  const cert = await X509CertificateGenerator.create({
    serialNumber: Math.floor(Math.random() * 1e9).toString(16),
    subject: options?.subject ?? 'CN=test-leaf, O=ACME',
    issuer: ca.cert.subject,
    notBefore: options?.notBefore ?? new Date(Date.now() - 24 * 3600 * 1000),
    notAfter: options?.notAfter ?? new Date(Date.now() + 30 * 24 * 3600 * 1000),
    signingAlgorithm: ca.signingAlgorithm,
    publicKey: keys.publicKey,
    signingKey: ca.privateKey,
    extensions: [
      new KeyUsagesExtension(
        options?.keyUsages ??
          KeyUsageFlags.digitalSignature | KeyUsageFlags.nonRepudiation,
        true,
      ),
    ],
  });

  return { cert, privateKey: keys.privateKey, signingAlgorithm: RSA_SIG };
}

function buildAnchor(ca: X509Certificate, country = 'EU'): TrustAnchor {
  const der = new Uint8Array(ca.rawData);
  return {
    fingerprint: createHash('sha256').update(der).digest('hex'),
    subject: ca.subject,
    issuer: ca.issuer,
    country,
    serviceTypes: ['QSeal', 'QSig'],
    certificate: ca,
    der,
  };
}

function tamper(pem: string): string {
  // Flip a single base64 char inside the body of the PEM. The flip targets a
  // line near the bottom, which is overwhelmingly likely to land in the CA
  // signature bytes — exactly the case a naive verifier would miss.
  const lines = pem.trim().split('\n');
  const targetIdx = lines.length - 4;
  const original = lines[targetIdx];
  if (!original) return pem;
  const ch = original[10];
  const flipped =
    original.slice(0, 10) + (ch === 'A' ? 'B' : 'A') + original.slice(11);
  lines[targetIdx] = flipped;
  return lines.join('\n');
}

describe('CertValidatorService', () => {
  let trustStore: TrustStoreService;
  let validator: CertValidatorService;
  let ca: IssuedPair;

  beforeAll(async () => {
    ca = await generateCa();
  });

  beforeEach(() => {
    trustStore = new TrustStoreService();
    validator = new CertValidatorService(trustStore, 'enforce');
  });

  it('refuses to validate while the trust store is empty', async () => {
    const leaf = await issueLeaf(ca);

    await expect(
      validator.validateLeafPem(leaf.cert.toString('pem')),
    ).rejects.toThrow(ServiceUnavailableException);
  });

  it('still rejects a malformed certificate while the trust store is empty', async () => {
    const result = await validator.validateLeafPem('not a certificate');

    expect(result).toMatchObject({ ok: false });
  });

  it('skips chain validation while the store is empty only in skip mode', async () => {
    const skipping = new CertValidatorService(trustStore, 'skip');
    const leaf = await issueLeaf(ca);

    const result = await skipping.validateLeafPem(leaf.cert.toString('pem'));

    expect(result).toMatchObject({ ok: true, matchedAnchor: null });
  });

  it('validates the chain in skip mode once anchors are loaded', async () => {
    const skipping = new CertValidatorService(trustStore, 'skip');
    trustStore.replaceAnchors([buildAnchor(ca.cert)]);
    const leaf = await issueLeaf(await generateCa('CN=Other CA, C=EU'));

    const result = await skipping.validateLeafPem(leaf.cert.toString('pem'));

    expect(result.ok).toBe(false);
  });

  it('accepts a leaf signed by a trusted anchor', async () => {
    trustStore.replaceAnchors([buildAnchor(ca.cert)]);
    const leaf = await issueLeaf(ca);

    const result = await validator.validateLeafPem(leaf.cert.toString('pem'));

    expect(result.ok).toBe(true);
    if ('matchedAnchor' in result) {
      expect(result.matchedAnchor.subject).toBe(ca.cert.subject);
      expect(result.fingerprint).toHaveLength(64);
    }
  });

  it('rejects a tampered leaf even when its public key is unchanged', async () => {
    trustStore.replaceAnchors([buildAnchor(ca.cert)]);
    const leaf = await issueLeaf(ca);
    const tamperedPem = tamper(leaf.cert.toString('pem'));

    const result = await validator.validateLeafPem(tamperedPem);

    expect(result.ok).toBe(false);
    if ('reason' in result) {
      expect(result.reason).toMatch(
        /signature could not be verified|Invalid X\.509/,
      );
    }
  });

  it('rejects a leaf signed by an untrusted CA', async () => {
    const otherCa = await generateCa('CN=Other CA, C=EU');
    trustStore.replaceAnchors([buildAnchor(ca.cert)]);
    const leaf = await issueLeaf(otherCa);

    const result = await validator.validateLeafPem(leaf.cert.toString('pem'));

    expect(result.ok).toBe(false);
    if ('reason' in result) {
      expect(result.reason).toMatch(
        /No trust anchor|signature could not be verified/,
      );
    }
  });

  it('rejects an expired leaf', async () => {
    trustStore.replaceAnchors([buildAnchor(ca.cert)]);
    const leaf = await issueLeaf(ca, {
      notBefore: new Date(Date.now() - 10 * 24 * 3600 * 1000),
      notAfter: new Date(Date.now() - 1 * 24 * 3600 * 1000),
    });

    const result = await validator.validateLeafPem(leaf.cert.toString('pem'));

    expect(result.ok).toBe(false);
    if ('reason' in result) expect(result.reason).toMatch(/expired/);
  });

  it('rejects a not-yet-valid leaf', async () => {
    trustStore.replaceAnchors([buildAnchor(ca.cert)]);
    const leaf = await issueLeaf(ca, {
      notBefore: new Date(Date.now() + 10 * 24 * 3600 * 1000),
      notAfter: new Date(Date.now() + 30 * 24 * 3600 * 1000),
    });

    const result = await validator.validateLeafPem(leaf.cert.toString('pem'));

    expect(result.ok).toBe(false);
    if ('reason' in result) expect(result.reason).toMatch(/not yet valid/);
  });

  it('rejects a leaf signed with SHA-1', async () => {
    const sha1Ca = await generateCa('CN=Legacy CA, C=EU', RSA_SHA1_SIG);
    trustStore.replaceAnchors([buildAnchor(sha1Ca.cert)]);
    const leaf = await issueLeaf(sha1Ca);

    const result = await validator.validateLeafPem(leaf.cert.toString('pem'));

    expect(result.ok).toBe(false);
    if ('reason' in result)
      expect(result.reason).toMatch(/hash algorithm "SHA-1" is not allowed/);
  });

  it('rejects a leaf without digitalSignature/nonRepudiation key usage', async () => {
    trustStore.replaceAnchors([buildAnchor(ca.cert)]);
    const leaf = await issueLeaf(ca, {
      keyUsages: KeyUsageFlags.dataEncipherment,
    });

    const result = await validator.validateLeafPem(leaf.cert.toString('pem'));

    expect(result.ok).toBe(false);
    if ('reason' in result) expect(result.reason).toMatch(/KeyUsage/);
  });
});
