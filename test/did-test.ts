/**
 * ============================================================
 *  EC P-256 (prime256v1) ↔ DID Key — Complete Implementation
 * ============================================================
 *
 *  Fully OpenSSL-compatible. Keys are PEM strings, identical
 *  to what these OpenSSL commands produce:
 *
 *    openssl ecparam -name prime256v1 -genkey -noout -out cc_private_key.pem
 *    openssl ec -in cc_private_key.pem -pubout -out cc_public_key.pem
 *
 *  Install:  npm install @noble/curves @scure/base
 *            npm install --save-dev typescript @types/node tsx
 *
 *  ── Usage modes ──────────────────────────────────────────────
 *
 *  1. Generate new keys and save to disk, then run tests:
 *       npx tsx did-key-final.ts --generate
 *       npx tsx did-key-final.ts --generate --out ./keys
 *
 *  2. Load existing PEM files from disk, then run tests:
 *       npx tsx did-key-final.ts --private ./cc_private_key.pem --public ./cc_public_key.pem
 *
 *  3. Auto-detect: look for cc_private_key.pem / cc_public_key.pem
 *     in the same folder as this script, generate if not found:
 *       npx tsx did-key-final.ts
 *
 *  Compile and run:
 *       npx tsc && node dist/did-key-final.js
 *
 * ============================================================
 */

import crypto                     from "node:crypto";
import fs                         from "node:fs";
import path                       from "node:path";
import { fileURLToPath }          from "node:url";
import { p256 }                   from "@noble/curves/nist.js";
import { base58 }                 from "@scure/base";

// ─── Types ───────────────────────────────────────────────────────────────────

export interface KeyPair {
  privateKeyPem: string;
  publicKeyPem:  string;
}

export interface SavedKeyPaths {
  privatePath: string;
  publicPath:  string;
}

export interface VerificationResult {
  valid:  boolean;
  reason: string;
}

export interface CliOptions {
  generate:    boolean;
  outDir:      string;
  privatePath: string | null;
  publicPath:  string | null;
}

// ─── Constants ───────────────────────────────────────────────────────────────

/**
 * P-256 multicodec identifier is 0x1200.
 * Varint-encoded → two bytes: [0x80, 0x24].
 * Tells any did:key resolver "this is a P-256 public key".
 */
const P256_MULTICODEC_PREFIX = new Uint8Array([0x80, 0x24]);

const SCRIPT_DIR        = path.dirname(fileURLToPath(import.meta.url));
const DEFAULT_PRIV_FILE = "cc_private_key.pem";
const DEFAULT_PUB_FILE  = "cc_public_key.pem";

// ─── Logging helpers ─────────────────────────────────────────────────────────

const log    = (msg: string): void  => console.log(`  ${msg}`);
const ok     = (msg: string): void  => console.log(`  ✅ ${msg}`);
const fail   = (msg: string): void  => console.log(`  ❌ ${msg}`);
const info   = (msg: string): void  => console.log(`  ℹ️  ${msg}`);
const sep    = (title: string): void => console.log(`\n${"─".repeat(60)}\n  ${title}\n${"─".repeat(60)}`);
const kv     = (k: string, v: string): void => console.log(`  ${k.padEnd(28)} ${v}`);

function assert(condition: boolean, msg: string): asserts condition {
  if (condition) ok(msg);
  else           { fail(msg); process.exit(1); }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  1. GENERATE KEY PAIR
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Generates an EC P-256 key pair as PEM strings.
 *
 * Private key → SEC1 PEM  (-----BEGIN EC PRIVATE KEY-----)
 * Public key  → SPKI PEM  (-----BEGIN PUBLIC KEY-----)
 *
 * Byte-for-byte identical to OpenSSL's prime256v1 output.
 */
export function generateKeyPair(): KeyPair {
  const { privateKey, publicKey } = crypto.generateKeyPairSync("ec", {
    namedCurve: "prime256v1",
    privateKeyEncoding: { type: "sec1",  format: "pem" },
    publicKeyEncoding:  { type: "spki",  format: "pem" },
  });
  return {
    privateKeyPem: privateKey as string,
    publicKeyPem:  publicKey  as string,
  };
}

// ═══════════════════════════════════════════════════════════════════════════════
//  2. SAVE / LOAD KEY PAIRS
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Saves a key pair to disk as two PEM files.
 * Private key is written with mode 0o600 (owner read/write only).
 */
export function saveKeyPairToDisk(
  privateKeyPem: string,
  publicKeyPem:  string,
  dir: string = SCRIPT_DIR,
): SavedKeyPaths {
  fs.mkdirSync(dir, { recursive: true });
  const privatePath = path.join(dir, DEFAULT_PRIV_FILE);
  const publicPath  = path.join(dir, DEFAULT_PUB_FILE);
  fs.writeFileSync(privatePath, privateKeyPem, { encoding: "utf8", mode: 0o600 });
  fs.writeFileSync(publicPath,  publicKeyPem,  { encoding: "utf8" });
  return { privatePath, publicPath };
}

/**
 * Reads a key pair from two PEM files on disk.
 * Throws with a descriptive message if either file is missing.
 */
export function loadKeyPairFromDisk(privatePath: string, publicPath: string): KeyPair {
  if (!fs.existsSync(privatePath)) {
    throw new Error(`Private key file not found: ${privatePath}`);
  }
  if (!fs.existsSync(publicPath)) {
    throw new Error(`Public key file not found: ${publicPath}`);
  }
  return {
    privateKeyPem: fs.readFileSync(privatePath, "utf8"),
    publicKeyPem:  fs.readFileSync(publicPath,  "utf8"),
  };
}

// ═══════════════════════════════════════════════════════════════════════════════
//  3. PUBLIC KEY PEM → DID KEY
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Converts an SPKI PEM public key to a did:key DID.
 *
 * Steps:
 *   1. Parse PEM → SPKI DER (ASN.1 structure with algorithm identifiers)
 *   2. Extract last 65 bytes = uncompressed public key (0x04 || x || y)
 *   3. Compress to 33 bytes: (0x02 if y even, 0x03 if y odd) || x
 *   4. Prepend P-256 multicodec prefix [0x80, 0x24]
 *   5. Base58btc-encode
 *   6. Prepend multibase prefix 'z' (means base58btc)
 *   7. Prepend 'did:key:'
 */
export function publicKeyPemToDid(publicKeyPem: string): string {
  const keyObject    = crypto.createPublicKey(publicKeyPem);
  const spkiDer      = keyObject.export({ type: "spki", format: "der" }) as Buffer;
  const uncompressed = new Uint8Array(spkiDer).slice(-65);

  if (uncompressed[0] !== 0x04) {
    throw new Error("Expected uncompressed EC point (0x04 prefix) in SPKI DER");
  }

  const x      = uncompressed.slice(1, 33);
  const y      = uncompressed.slice(33, 65);
  // Last byte of y determines parity: even → 0x02, odd → 0x03
  const prefix = (y[31] & 1) === 0 ? 0x02 : 0x03;
  const compressed = new Uint8Array([prefix, ...x]);

  const multicodec = new Uint8Array([...P256_MULTICODEC_PREFIX, ...compressed]);
  return "did:key:z" + base58.encode(multicodec);
}

// ═══════════════════════════════════════════════════════════════════════════════
//  4. VERIFY PUBLIC KEY MATCHES DID
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Verifies that a PEM public key corresponds to a given did:key DID.
 *
 * Because the public key is directly embedded in the DID (no hashing),
 * verification is: re-derive the DID from the key and compare strings.
 */
export function verifyPublicKeyMatchesDid(
  did:          string,
  publicKeyPem: string,
): VerificationResult {
  const derived = publicKeyPemToDid(publicKeyPem);
  const valid   = derived === did;
  return {
    valid,
    reason: valid
      ? "Derived DID matches the provided DID exactly."
      : `Derived DID does not match.\n      Expected : ${did}\n      Got      : ${derived}`,
  };
}

// ═══════════════════════════════════════════════════════════════════════════════
//  5. DID KEY → PUBLIC KEY PEM
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Reconstructs the SPKI PEM public key from a did:key DID.
 * Full lossless round-trip: PEM → DID → PEM yields identical bytes.
 *
 * Steps:
 *   1. Strip 'did:key:z' (z = base58btc multibase prefix)
 *   2. Base58btc-decode → multicodec bytes
 *   3. Validate and strip 2-byte P-256 prefix [0x80, 0x24]
 *   4. Decompress 33-byte key → full 65-byte (x, y) point via @noble/curves
 *   5. Build JWK from x, y → import → export as SPKI PEM
 */
export function didToPublicKeyPem(did: string): string {
  if (!did.startsWith("did:key:z")) {
    throw new Error("Only did:key with base58btc multibase ('z') is supported");
  }

  const decoded = base58.decode(did.slice("did:key:z".length));

  if (decoded[0] !== 0x80 || decoded[1] !== 0x24) {
    throw new Error(
      `Not a P-256 did:key — expected multicodec prefix [0x80, 0x24], ` +
      `got [0x${decoded[0].toString(16)}, 0x${decoded[1].toString(16)}]`,
    );
  }

  const compressed   = decoded.slice(2); // 33 bytes
  const point        = p256.Point.fromHex(Buffer.from(compressed).toString("hex"));
  const uncompressed = point.toBytes(false); // false = uncompressed (65 bytes, 0x04 || x || y)

  const x = Buffer.from(uncompressed.slice(1, 33)).toString("base64url");
  const y = Buffer.from(uncompressed.slice(33, 65)).toString("base64url");

  const keyObject = crypto.createPublicKey({
    key:    { kty: "EC", crv: "P-256", x, y } as crypto.JsonWebKey,
    format: "jwk",
  });

  return keyObject.export({ type: "spki", format: "pem" }) as string;
}

// ═══════════════════════════════════════════════════════════════════════════════
//  CLI ARGUMENT PARSING
// ═══════════════════════════════════════════════════════════════════════════════

function parseArgs(): CliOptions {
  const args = process.argv.slice(2);
  const opts: CliOptions = {
    generate:    false,
    outDir:      SCRIPT_DIR,
    privatePath: null,
    publicPath:  null,
  };

  for (let i = 0; i < args.length; i++) {
    switch (args[i]) {
      case "--generate": opts.generate    = true;                        break;
      case "--out":      opts.outDir      = path.resolve(args[++i]);    break;
      case "--private":  opts.privatePath = path.resolve(args[++i]);    break;
      case "--public":   opts.publicPath  = path.resolve(args[++i]);    break;
      case "--help":
        console.log(`
Usage:
  npx tsx did-key-final.ts                                   Auto-detect or generate
  npx tsx did-key-final.ts --generate                        Generate + save to script dir
  npx tsx did-key-final.ts --generate --out ./keys           Generate + save to ./keys/
  npx tsx did-key-final.ts --private ./priv.pem \\
                           --public  ./pub.pem               Load specific files
        `);
        process.exit(0);
    }
  }

  return opts;
}

// ═══════════════════════════════════════════════════════════════════════════════
//  KEY ACQUISITION (generate or load, with auto-detect)
// ═══════════════════════════════════════════════════════════════════════════════

function acquireKeys(opts: CliOptions): KeyPair {
  // ── Mode 1: explicit --private / --public paths ───────────────────────────
  if (opts.privatePath !== null || opts.publicPath !== null) {
    const privPath = opts.privatePath ?? path.join(SCRIPT_DIR, DEFAULT_PRIV_FILE);
    const pubPath  = opts.publicPath  ?? path.join(SCRIPT_DIR, DEFAULT_PUB_FILE);

    sep("KEY SOURCE — Loading from specified PEM files");
    kv("Private key file:", privPath);
    kv("Public key file: ", pubPath);

    const keys = loadKeyPairFromDisk(privPath, pubPath);
    ok(`Private key loaded (${keys.privateKeyPem.split("\n").length - 2} lines)`);
    ok(`Public key loaded  (${keys.publicKeyPem.split("\n").length - 2} lines)`);
    return keys;
  }

  // ── Mode 2: --generate flag → always create fresh keys ───────────────────
  if (opts.generate) {
    sep("KEY SOURCE — Generating new EC P-256 key pair");
    const keys = generateKeyPair();
    const { privatePath, publicPath } = saveKeyPairToDisk(
      keys.privateKeyPem, keys.publicKeyPem, opts.outDir,
    );
    ok("Key pair generated (prime256v1 / P-256)");
    kv("Private key saved:", privatePath);
    kv("  permissions:",     "0600 (owner read/write only)");
    kv("Public key saved: ", publicPath);
    return keys;
  }

  // ── Mode 3: auto-detect — look for default filenames next to this script ──
  const defaultPriv = path.join(SCRIPT_DIR, DEFAULT_PRIV_FILE);
  const defaultPub  = path.join(SCRIPT_DIR, DEFAULT_PUB_FILE);

  if (fs.existsSync(defaultPriv) && fs.existsSync(defaultPub)) {
    sep("KEY SOURCE — Auto-detected existing PEM files");
    kv("Private key file:", defaultPriv);
    kv("Public key file: ", defaultPub);
    const keys = loadKeyPairFromDisk(defaultPriv, defaultPub);
    ok("Both PEM files found and loaded");
    return keys;
  }

  // ── Mode 4: auto-detect found nothing → generate and save ─────────────────
  sep("KEY SOURCE — No PEM files found, generating new key pair");
  info(`Looked for: ${defaultPriv}`);
  info(`Looked for: ${defaultPub}`);
  info("Neither found — generating fresh keys and saving to script directory");

  const keys = generateKeyPair();
  const { privatePath, publicPath } = saveKeyPairToDisk(
    keys.privateKeyPem, keys.publicKeyPem, SCRIPT_DIR,
  );
  ok("Key pair generated (prime256v1 / P-256)");
  kv("Private key saved:", privatePath);
  kv("  permissions:",     "0600 (owner read/write only)");
  kv("Public key saved: ", publicPath);
  info("Next run will auto-load these files instead of generating new ones.");
  return keys;
}

// ═══════════════════════════════════════════════════════════════════════════════
//  SELF-TESTING SUITE
// ═══════════════════════════════════════════════════════════════════════════════

console.log("\n╔══════════════════════════════════════════════════════════╗");
console.log(  "║   EC P-256 ↔ DID Key — Complete Self-Testing Suite     ║");
console.log(  "╚══════════════════════════════════════════════════════════╝");

const opts = parseArgs();

// ─── Acquire keys (generate or load) ─────────────────────────────────────────

const { privateKeyPem, publicKeyPem } = acquireKeys(opts);

// ─── Display loaded / generated keys ─────────────────────────────────────────

sep("KEYS IN USE");
log("Private Key (SEC1 PEM):");
privateKeyPem.trim().split("\n").forEach(line => log(`  ${line}`));
log("");
log("Public Key (SPKI PEM):");
publicKeyPem.trim().split("\n").forEach(line => log(`  ${line}`));

assert(privateKeyPem.includes("BEGIN EC PRIVATE KEY"), "Private key is SEC1 PEM format");
assert(publicKeyPem.includes("BEGIN PUBLIC KEY"),      "Public key is SPKI PEM format");

// ─── TEST 1: Public Key → DID ────────────────────────────────────────────────

sep("TEST 1 — Derive DID Key from Public Key PEM");
log("Converting public key PEM → did:key...");
log("Internally: PEM → SPKI DER → uncompressed point → compress → multicodec → base58btc → did:key");
log("");

const did = publicKeyPemToDid(publicKeyPem);

kv("DID:",              did);
kv("DID length:",       `${did.length} chars`);
kv("Multibase prefix:", "'z' = base58btc ✓");
kv("Multicodec prefix:", "[0x80, 0x24] = P-256 (0x1200) ✓");

assert(did.startsWith("did:key:z"), "DID starts with 'did:key:z'");
assert(did.length > 50,            "DID has plausible length for a P-256 key");

// ─── TEST 2: Verify Matching Key ─────────────────────────────────────────────

sep("TEST 2 — Verify Correct Public Key Matches DID");
log(`DID          : ${did}`);
log(`Key (excerpt): ${publicKeyPem.split("\n")[1].slice(0, 40)}...`);
log("");

const matchResult = verifyPublicKeyMatchesDid(did, publicKeyPem);
kv("Valid:", String(matchResult.valid));
log(`  Reason: ${matchResult.reason}`);

assert(matchResult.valid, "Correct public key verified against its own DID");

// ─── TEST 3: Verify Wrong Key Does NOT Match ─────────────────────────────────

sep("TEST 3 — Verify a Different Public Key Does NOT Match DID");
log("Generating a second, unrelated key pair (in memory only, not saved)...");

const { publicKeyPem: wrongPublicKeyPem } = generateKeyPair();
const wrongDid = publicKeyPemToDid(wrongPublicKeyPem);
log("");
kv("Original DID :", did.slice(0, 52) + "...");
kv("Wrong key DID:", wrongDid.slice(0, 52) + "...");
log("");

const wrongResult = verifyPublicKeyMatchesDid(did, wrongPublicKeyPem);
kv("Valid:", String(wrongResult.valid));
log(`  Reason: ${wrongResult.reason}`);

assert(!wrongResult.valid, "Different public key correctly rejected — DIDs differ");

// ─── TEST 4: DID → Public Key PEM (Round-Trip) ───────────────────────────────

sep("TEST 4 — Convert DID Back to Public Key PEM (Round-Trip)");
log(`Input DID: ${did}`);
log("");
log("Internally: strip did:key:z → base58btc decode → strip multicodec prefix");
log("            → decompress EC point (noble/curves) → build JWK → SPKI PEM");
log("");

const recoveredPem = didToPublicKeyPem(did);

log("Recovered Public Key (SPKI PEM):");
recoveredPem.trim().split("\n").forEach(line => log(`  ${line}`));
log("");
kv("Original  (first 40 chars):", publicKeyPem.split("\n")[1].slice(0, 40)  + "...");
kv("Recovered (first 40 chars):", recoveredPem.split("\n")[1].slice(0, 40)  + "...");

assert(
  recoveredPem.trim() === publicKeyPem.trim(),
  "Round-trip: recovered PEM is byte-for-byte identical to original",
);

// ─── TEST 5: Tampered DID Rejected ───────────────────────────────────────────

sep("TEST 5 — Tampered DID Is Rejected");

// 0, O, I, l are intentionally excluded from the base58 alphabet
const tamperedDid = did.slice(0, -4) + "0OIl";
log(`Original DID : ${did}`);
log(`Tampered DID : ${tamperedDid}`);
log("  (last 4 chars replaced with '0OIl' — chars not in base58 alphabet)");
log("");

try {
  didToPublicKeyPem(tamperedDid);
  fail("Should have thrown — tampered DID was accepted (unexpected)");
  process.exit(1);
} catch (err) {
  ok("Tampered DID correctly rejected");
  log(`  Error: "${(err as Error).message}"`);
}

// ─── TEST 6: Wrong DID Method Rejected ───────────────────────────────────────

sep("TEST 6 — Wrong DID Method Is Rejected");

const wrongMethodDid = "did:web:example.com";
log(`Input: ${wrongMethodDid}`);
log("  (did:web is a different DID method — not did:key)");
log("");

try {
  didToPublicKeyPem(wrongMethodDid);
  fail("Should have thrown — wrong DID method accepted (unexpected)");
  process.exit(1);
} catch (err) {
  ok("Wrong DID method correctly rejected");
  log(`  Error: "${(err as Error).message}"`);
}

// ─── TEST 7: Missing PEM File Gives a Clear Error ────────────────────────────

sep("TEST 7 — Missing PEM File Gives a Clear Error");

const fakePath = "/tmp/this_file_does_not_exist_abc123.pem";
log(`Attempting to load: ${fakePath}`);
log("");

try {
  loadKeyPairFromDisk(fakePath, fakePath);
  fail("Should have thrown — missing file accepted (unexpected)");
  process.exit(1);
} catch (err) {
  ok("Missing file correctly rejected");
  log(`  Error: "${(err as Error).message}"`);
}

// ─── SUMMARY ─────────────────────────────────────────────────────────────────

console.log("\n╔══════════════════════════════════════════════════════════╗");
console.log(  "║  All 7 tests passed ✅                                   ║");
console.log(  "╠══════════════════════════════════════════════════════════╣");
console.log(  "║  generateKeyPair()              → SEC1 + SPKI PEM       ║");
console.log(  "║  saveKeyPairToDisk(...)         → writes .pem files     ║");
console.log(  "║  loadKeyPairFromDisk(...)       → reads .pem files      ║");
console.log(  "║  publicKeyPemToDid(pem)         → did:key:z...          ║");
console.log(  "║  verifyPublicKeyMatchesDid(...) → { valid, reason }     ║");
console.log(  "║  didToPublicKeyPem(did)         → SPKI PEM (lossless)   ║");
console.log(  "╚══════════════════════════════════════════════════════════╝");
console.log(`\n  Run with --help to see all CLI options.\n`);
