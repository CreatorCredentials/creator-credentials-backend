import { mkdtempSync, rmSync, writeFileSync } from 'fs';
import { tmpdir } from 'os';
import * as path from 'path';
import { Crypto } from '@peculiar/webcrypto';
import {
  BasicConstraintsExtension,
  KeyUsageFlags,
  KeyUsagesExtension,
  X509CertificateGenerator,
  cryptoProvider,
} from '@peculiar/x509';

export const PLATFORM_DID = 'did:web:liccium.com';

const RSA_SHA256 = {
  name: 'RSASSA-PKCS1-v1_5',
  hash: 'SHA-256',
  publicExponent: new Uint8Array([1, 0, 1]),
  modulusLength: 2048,
} as const;

const DAY_MS = 24 * 60 * 60 * 1000;

export interface EphemeralPlatformSigner {
  /** Base64 DER of the certificate, as it appears in the `x5c` header. */
  certificateBase64: string;
  /** Removes the temporary certificate file and the environment overrides. */
  cleanup(): void;
}

/**
 * Replaces the platform signer (`HALCOM_CERT_PRIVATE_KEY` + `certificates/LICCIUM.der`)
 * with a key pair and a self-signed certificate generated for this test run, so specs
 * never depend on the real private key, which is not part of the repository.
 */
export async function installEphemeralPlatformSigner(): Promise<EphemeralPlatformSigner> {
  const webcrypto = new Crypto();
  cryptoProvider.set(webcrypto);

  const keys = await webcrypto.subtle.generateKey(RSA_SHA256, true, [
    'sign',
    'verify',
  ]);
  const subject = `CN=${PLATFORM_DID}, O=Test platform, C=EU`;
  const certificate = await X509CertificateGenerator.createSelfSigned({
    serialNumber: '01',
    name: subject,
    notBefore: new Date(Date.now() - DAY_MS),
    notAfter: new Date(Date.now() + 365 * DAY_MS),
    signingAlgorithm: RSA_SHA256,
    keys,
    extensions: [
      new BasicConstraintsExtension(false, undefined, true),
      new KeyUsagesExtension(
        KeyUsageFlags.digitalSignature | KeyUsageFlags.nonRepudiation,
        true,
      ),
    ],
  });

  const pkcs8 = Buffer.from(
    await webcrypto.subtle.exportKey('pkcs8', keys.privateKey),
  );
  const privateKeyPem = [
    '-----BEGIN PRIVATE KEY-----',
    pkcs8
      .toString('base64')
      .match(/.{1,64}/g)!
      .join('\n'),
    '-----END PRIVATE KEY-----',
  ].join('\n');

  const dir = mkdtempSync(path.join(tmpdir(), 'platform-signer-'));
  const derPath = path.join(dir, 'platform.der');
  writeFileSync(derPath, Buffer.from(certificate.rawData));

  const previous = {
    key: process.env.HALCOM_CERT_PRIVATE_KEY,
    der: process.env.HALCOM_CERT_DER_PATH,
  };
  process.env.HALCOM_CERT_PRIVATE_KEY = privateKeyPem;
  process.env.HALCOM_CERT_DER_PATH = derPath;

  return {
    certificateBase64: Buffer.from(certificate.rawData).toString('base64'),
    cleanup() {
      rmSync(dir, { recursive: true, force: true });
      restore('HALCOM_CERT_PRIVATE_KEY', previous.key);
      restore('HALCOM_CERT_DER_PATH', previous.der);
    },
  };
}

function restore(name: string, value: string | undefined): void {
  if (value === undefined) delete process.env[name];
  else process.env[name] = value;
}
