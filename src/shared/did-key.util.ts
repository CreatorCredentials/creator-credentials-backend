import * as crypto from 'crypto';
import { p256 } from '@noble/curves/nist';
import { base58 } from '@scure/base';

/**
 * P-256 multicodec identifier (0x1200) varint-encoded → [0x80, 0x24].
 * Tells any did:key resolver "this is a P-256 public key".
 */
const P256_MULTICODEC_PREFIX = new Uint8Array([0x80, 0x24]);

/**
 * Converts an SPKI PEM public key (EC P-256) to a did:key DID.
 *
 * Steps:
 *   1. Parse PEM → SPKI DER
 *   2. Extract last 65 bytes = uncompressed public key (0x04 || x || y)
 *   3. Compress to 33 bytes: (0x02 if y even, 0x03 if y odd) || x
 *   4. Prepend P-256 multicodec prefix [0x80, 0x24]
 *   5. Base58btc-encode
 *   6. Prepend multibase prefix 'z' (base58btc) and 'did:key:'
 */
export function publicKeyPemToDid(publicKeyPem: string): string {
  const keyObject = crypto.createPublicKey(publicKeyPem);
  const spkiDer = keyObject.export({ type: 'spki', format: 'der' }) as Buffer;
  const uncompressed = new Uint8Array(spkiDer).slice(-65);

  if (uncompressed[0] !== 0x04) {
    throw new Error(
      'Expected uncompressed EC point (0x04 prefix) in SPKI DER',
    );
  }

  const x = uncompressed.slice(1, 33);
  const y = uncompressed.slice(33, 65);
  const prefix = (y[31] & 1) === 0 ? 0x02 : 0x03;
  const compressed = new Uint8Array([prefix, ...x]);

  const multicodec = new Uint8Array([...P256_MULTICODEC_PREFIX, ...compressed]);
  return 'did:key:z' + base58.encode(multicodec);
}

/**
 * Reconstructs the SPKI PEM public key from a did:key DID (P-256 only).
 * Lossless round-trip: publicKeyPemToDid → didToPublicKeyPem yields identical PEM.
 *
 * Steps:
 *   1. Strip 'did:key:z' (z = base58btc multibase prefix)
 *   2. Base58btc-decode → multicodec bytes
 *   3. Validate and strip 2-byte P-256 prefix [0x80, 0x24]
 *   4. Decompress 33-byte key → full 65-byte (x, y) point via @noble/curves
 *   5. Build JWK from x, y → import → export as SPKI PEM
 */
export function didToPublicKeyPem(did: string): string {
  if (!did.startsWith('did:key:z')) {
    throw new Error(
      "Only did:key with base58btc multibase ('z') is supported",
    );
  }

  const decoded = base58.decode(did.slice('did:key:z'.length));

  if (decoded[0] !== 0x80 || decoded[1] !== 0x24) {
    throw new Error(
      `Not a P-256 did:key — expected multicodec prefix [0x80, 0x24], ` +
        `got [0x${decoded[0].toString(16)}, 0x${decoded[1].toString(16)}]`,
    );
  }

  const compressed = decoded.slice(2);
  const point = p256.Point.fromHex(Buffer.from(compressed).toString('hex'));
  const uncompressed = point.toBytes(false);

  const x = Buffer.from(uncompressed.slice(1, 33)).toString('base64url');
  const y = Buffer.from(uncompressed.slice(33, 65)).toString('base64url');

  const keyObject = crypto.createPublicKey({
    key: { kty: 'EC', crv: 'P-256', x, y } as crypto.JsonWebKey,
    format: 'jwk',
  });

  return keyObject.export({ type: 'spki', format: 'pem' }) as string;
}

/**
 * Verifies that a PEM public key corresponds to a given did:key DID.
 * Because the public key is directly embedded (no hashing), verification
 * re-derives the DID from the key and compares strings.
 */
export function verifyPublicKeyMatchesDid(
  did: string,
  publicKeyPem: string,
): { valid: boolean; reason: string } {
  const derived = publicKeyPemToDid(publicKeyPem);
  const valid = derived === did;
  return {
    valid,
    reason: valid
      ? 'Derived DID matches the provided DID exactly.'
      : `Derived DID does not match. Expected: ${did} — Got: ${derived}`,
  };
}
