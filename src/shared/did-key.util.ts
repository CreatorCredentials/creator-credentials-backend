import * as crypto from 'crypto';

// ─── Base58 (alphabet) ────────────────────────────────────────────────
const BASE58_CHARS =
  '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

function base58Encode(bytes: Uint8Array): string {
  let leadingZeros = 0;
  for (const b of bytes) {
    if (b !== 0) break;
    leadingZeros++;
  }
  let num = 0n;
  for (const b of bytes) num = num * 256n + BigInt(b);
  let out = '';
  while (num > 0n) {
    out = BASE58_CHARS[Number(num % 58n)] + out;
    num /= 58n;
  }
  return '1'.repeat(leadingZeros) + out;
}

function base58Decode(str: string): Uint8Array {
  let leadingZeros = 0;
  for (const c of str) {
    if (c !== '1') break;
    leadingZeros++;
  }
  let num = 0n;
  for (const c of str) {
    const idx = BASE58_CHARS.indexOf(c);
    if (idx === -1) throw new Error(`Invalid base58 character: '${c}'`);
    num = num * 58n + BigInt(idx);
  }
  const out: number[] = [];
  while (num > 0n) {
    out.unshift(Number(num & 0xffn));
    num >>= 8n;
  }
  const result = new Uint8Array(leadingZeros + out.length);
  out.forEach((b, i) => (result[leadingZeros + i] = b));
  return result;
}

// ─── P-256 curve constants ────────────────────────────────────────────────────
// p ≡ 3 (mod 4), so the square root of y² mod p is: y = (y²)^((p+1)/4) mod p
const P256_P =
  0xffffffff00000001000000000000000000000000ffffffffffffffffffffffffn;
const P256_A = P256_P - 3n; // a = -3 mod p
const P256_B =
  0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604bn;

function modpow(base: bigint, exp: bigint, mod: bigint): bigint {
  let result = 1n;
  let b = base % mod;
  let e = exp;
  while (e > 0n) {
    if (e & 1n) result = (result * b) % mod;
    e >>= 1n;
    b = (b * b) % mod;
  }
  return result;
}

/**
 * Decompresses a 33-byte P-256 compressed public key to 65-byte uncompressed
 * (0x04 || x || y) using the P-256 curve equation: y² = x³ + ax + b (mod p).
 */
function decompressP256Point(compressed: Uint8Array): Uint8Array {
  if (compressed.length !== 33 || (compressed[0] !== 0x02 && compressed[0] !== 0x03)) {
    throw new Error('Invalid compressed P-256 point');
  }
  const prefix = compressed[0];
  const x = BigInt('0x' + Buffer.from(compressed.slice(1)).toString('hex'));
  const rhs = ((modpow(x, 3n, P256_P) + P256_A * x + P256_B) % P256_P + P256_P) % P256_P;
  let y = modpow(rhs, (P256_P + 1n) / 4n, P256_P);
  const yIsEven = (y & 1n) === 0n;
  if ((prefix === 0x02) !== yIsEven) y = P256_P - y;
  const yBytes = Buffer.from(y.toString(16).padStart(64, '0'), 'hex');
  return new Uint8Array([0x04, ...compressed.slice(1), ...yBytes]);
}

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
  return 'did:key:z' + base58Encode(multicodec);
}

/**
 * Reconstructs the SPKI PEM public key from a did:key DID (P-256 only).
 * Lossless round-trip: publicKeyPemToDid → didToPublicKeyPem yields identical PEM.
 *
 * Steps:
 *   1. Strip 'did:key:z' (z = base58btc multibase prefix)
 *   2. Base58btc-decode → multicodec bytes
 *   3. Validate and strip 2-byte P-256 prefix [0x80, 0x24]
 *   4. Decompress 33-byte key → full 65-byte (x, y) point via P-256 curve math
 *   5. Build JWK from x, y → import → export as SPKI PEM
 */
export function didToPublicKeyPem(did: string): string {
  if (!did.startsWith('did:key:z')) {
    throw new Error(
      "Only did:key with base58btc multibase ('z') is supported",
    );
  }

  const decoded = base58Decode(did.slice('did:key:z'.length));

  if (decoded[0] !== 0x80 || decoded[1] !== 0x24) {
    throw new Error(
      `Not a P-256 did:key — expected multicodec prefix [0x80, 0x24], ` +
        `got [0x${decoded[0].toString(16)}, 0x${decoded[1].toString(16)}]`,
    );
  }

  const compressed = decoded.slice(2);
  const uncompressed = decompressP256Point(compressed);

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
