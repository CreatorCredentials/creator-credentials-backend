import * as crypto from 'crypto';
import { normalizeEcdsaSignature } from 'src/credentials/signature-encoding';

const COMPACT_JWS_PARTS = 3;
const RS256 = 'RS256';
const ES256 = 'ES256';
const KEY_TYPE_BY_ALGORITHM: Record<string, crypto.KeyType> = {
  [RS256]: 'rsa',
  [ES256]: 'ec',
};

export type JwsHeader = {
  alg?: string;
  x5c?: string[];
  [claim: string]: unknown;
};

export type ParsedJws = {
  header: JwsHeader;
  payload: Record<string, unknown>;
  /** `<b64 header>.<b64 payload>`, the bytes the signature covers. */
  signingInput: string;
  signature: Buffer;
};

export class MalformedJwsError extends Error {}

/** Splits and decodes a compact JWS; throws MalformedJwsError on anything that is not one. */
export function parseCompactJws(token: unknown): ParsedJws {
  if (typeof token !== 'string') {
    throw new MalformedJwsError('jwt must be a string');
  }
  const parts = token.trim().split('.');
  if (parts.length !== COMPACT_JWS_PARTS || parts.some((part) => !part)) {
    throw new MalformedJwsError('jwt must be a compact JWS with three parts');
  }
  const [encodedHeader, encodedPayload, encodedSignature] = parts;
  return {
    header: decodeJsonObject(encodedHeader, 'header'),
    payload: decodeJsonObject(encodedPayload, 'payload'),
    signingInput: `${encodedHeader}.${encodedPayload}`,
    signature: Buffer.from(encodedSignature, 'base64url'),
  };
}

/** The certificate that signed the JWS: the first `x5c` entry, or undefined when absent or unreadable. */
export function leafCertificateOf(
  header: JwsHeader,
): crypto.X509Certificate | undefined {
  const leaf = header.x5c?.[0];
  if (typeof leaf !== 'string') {
    return undefined;
  }
  try {
    return new crypto.X509Certificate(Buffer.from(leaf, 'base64'));
  } catch {
    return undefined;
  }
}

/**
 * Verifies the JWS against the leaf certificate's public key. RS256 is
 * PKCS#1 v1.5; ES256 accepts the raw `r || s` form and the DER form older
 * tokens carry. Any mismatch between algorithm and key type fails.
 */
export function verifyJwsSignature(
  jws: ParsedJws,
  certificate: crypto.X509Certificate,
): boolean {
  const algorithm = jws.header.alg;
  const publicKey = certificate.publicKey;
  if (KEY_TYPE_BY_ALGORITHM[algorithm] !== publicKey.asymmetricKeyType) {
    return false;
  }
  try {
    return algorithm === ES256
      ? verifyEcdsa(publicKey, jws.signingInput, jws.signature)
      : verifyRsa(publicKey, jws.signingInput, jws.signature);
  } catch {
    return false;
  }
}

function verifyEcdsa(
  publicKey: crypto.KeyObject,
  signingInput: string,
  signature: Buffer,
): boolean {
  return crypto.verify(
    'sha256',
    Buffer.from(signingInput),
    { key: publicKey, dsaEncoding: 'ieee-p1363' },
    normalizeEcdsaSignature(signature),
  );
}

function verifyRsa(
  publicKey: crypto.KeyObject,
  signingInput: string,
  signature: Buffer,
): boolean {
  return crypto.verify(
    'sha256',
    Buffer.from(signingInput),
    publicKey,
    signature,
  );
}

function decodeJsonObject(
  encoded: string,
  part: string,
): Record<string, unknown> {
  let decoded: unknown;
  try {
    decoded = JSON.parse(Buffer.from(encoded, 'base64url').toString('utf8'));
  } catch {
    throw new MalformedJwsError(`jwt ${part} is not base64url JSON`);
  }
  if (!isPlainObject(decoded)) {
    throw new MalformedJwsError(`jwt ${part} must be a JSON object`);
  }
  return decoded;
}

export function isPlainObject(
  value: unknown,
): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}
