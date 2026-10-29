import { isIP } from 'net';
import { lookup } from 'dns/promises';
import {
  bitLength,
  decodeBitstring,
  isBitSet,
} from 'src/status-list/bitstring';
import {
  STATUS_LIST_CREDENTIAL_TYPE,
  STATUS_LIST_ENTRY_TYPE,
  STATUS_LIST_PURPOSE,
  STATUS_LIST_SIZE,
  STATUS_LIST_SUBJECT_TYPE,
} from 'src/status-list/status-list.constants';
import {
  isPlainObject,
  leafCertificateOf,
  MalformedJwsError,
  parseCompactJws,
  verifyJwsSignature,
} from './jws';
import { RevocationErrorReason } from './verification.types';

/** A revocation entry of `credentialStatus`, validated as W3C Bitstring Status List §2.1 requires. */
export type StatusListEntry = {
  statusListIndex: number;
  statusListCredential: string;
};

/** The failure of one step of the validate algorithm (§3.2), by its spec name. */
export class StatusListCheckError extends Error {
  constructor(
    readonly reason: RevocationErrorReason,
    message: string,
  ) {
    super(message);
  }
}

const DECIMAL_DIGITS = /^\d+$/;
const DEFAULT_STATUS_SIZE = 1;
const HTTPS = 'https:';
const DATA_URL_VC_JWT_PREFIX = 'data:application/vc+jwt,';
const PRIVATE_IPV4 = [
  /^10\./,
  /^127\./,
  /^169\.254\./,
  /^172\.(1[6-9]|2\d|3[01])\./,
  /^192\.168\./,
  /^0\./,
];
const PRIVATE_IPV6 = [/^::1$/, /^::$/, /^f[cd]/i, /^fe[89ab]/i, /^::ffff:/i];

/**
 * The revocation entry among `credentialStatus` (one entry or a list),
 * or undefined when the credential has none. Throws MALFORMED_VALUE_ERROR
 * when the entry exists but breaks the data model.
 */
export function revocationEntryOf(
  credentialStatus: unknown,
): StatusListEntry | undefined {
  const entries = (
    Array.isArray(credentialStatus) ? credentialStatus : [credentialStatus]
  ).filter(isPlainObject);
  const entry = entries.find(
    (candidate) =>
      candidate.type === STATUS_LIST_ENTRY_TYPE &&
      candidate.statusPurpose === STATUS_LIST_PURPOSE,
  );
  if (!entry) {
    return undefined;
  }
  const index = entry.statusListIndex;
  if (typeof index !== 'string' || !DECIMAL_DIGITS.test(index)) {
    throw new StatusListCheckError(
      'MALFORMED_VALUE_ERROR',
      'statusListIndex must be a base-10 integer string',
    );
  }
  if (typeof entry.statusListCredential !== 'string') {
    throw new StatusListCheckError(
      'MALFORMED_VALUE_ERROR',
      'statusListCredential must be a URL string',
    );
  }
  const statusSize = entry.statusSize ?? DEFAULT_STATUS_SIZE;
  if (statusSize !== DEFAULT_STATUS_SIZE) {
    throw new StatusListCheckError(
      'UNSUPPORTED_STATUS_SIZE',
      `statusSize ${String(
        statusSize,
      )} is not supported; only single-bit revocation lists are`,
    );
  }
  return {
    statusListIndex: Number(index),
    statusListCredential: entry.statusListCredential,
  };
}

/** Refuses anything but a public https URL, before any connection is made. */
export async function assertFetchableListUrl(url: string): Promise<void> {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    throw new StatusListCheckError(
      'MALFORMED_VALUE_ERROR',
      'statusListCredential is not a URL',
    );
  }
  if (parsed.protocol !== HTTPS) {
    throw new StatusListCheckError(
      'STATUS_RETRIEVAL_ERROR',
      'status lists are fetched over https only',
    );
  }
  const host = parsed.hostname.replace(/^\[|\]$/g, '');
  const addresses = isIP(host)
    ? [host]
    : (await lookup(host, { all: true })).map((entry) => entry.address);
  if (addresses.length === 0 || addresses.some(isPrivateAddress)) {
    throw new StatusListCheckError(
      'STATUS_RETRIEVAL_ERROR',
      `status list host ${parsed.hostname} is not a public address`,
    );
  }
}

/**
 * The verified status list credential out of a fetched response body:
 * a compact JWS, our JSON form with `proof.jwt`, or an enveloped credential
 * with a `data:application/vc+jwt,` id. Anything else cannot be verified here.
 */
export function verifiedListCredential(body: unknown): Record<string, unknown> {
  const token = compactJwsOf(body);
  let jws;
  try {
    jws = parseCompactJws(token);
  } catch (error) {
    if (error instanceof MalformedJwsError) {
      throw new StatusListCheckError(
        'STATUS_VERIFICATION_ERROR',
        `status list is not a verifiable JWS: ${error.message}`,
      );
    }
    throw error;
  }
  const certificate = leafCertificateOf(jws.header);
  if (!certificate || !verifyJwsSignature(jws, certificate)) {
    throw new StatusListCheckError(
      'STATUS_VERIFICATION_ERROR',
      'status list signature does not verify against its x5c certificate',
    );
  }
  return jws.payload;
}

/** Checks the list credential against §2.2 and the entry (§3.2 steps 5–10) and reads the bit. */
export function readRevocationBit(
  list: Record<string, unknown>,
  entry: StatusListEntry,
  now: Date,
): boolean {
  const subject = isPlainObject(list.credentialSubject)
    ? list.credentialSubject
    : undefined;
  if (
    !asArray(list.type).includes(STATUS_LIST_CREDENTIAL_TYPE) ||
    !subject ||
    subject.type !== STATUS_LIST_SUBJECT_TYPE ||
    typeof subject.encodedList !== 'string'
  ) {
    throw new StatusListCheckError(
      'STATUS_VERIFICATION_ERROR',
      'response is not a BitstringStatusListCredential',
    );
  }
  if (!isInValidityWindow(list, now)) {
    throw new StatusListCheckError(
      'STATUS_VERIFICATION_ERROR',
      'status list is outside its validity window',
    );
  }
  if (!asArray(subject.statusPurpose).includes(STATUS_LIST_PURPOSE)) {
    throw new StatusListCheckError(
      'STATUS_VERIFICATION_ERROR',
      `status list purpose does not include "${STATUS_LIST_PURPOSE}"`,
    );
  }
  const bits = decodeBitstring(subject.encodedList);
  if (bitLength(bits) < STATUS_LIST_SIZE) {
    throw new StatusListCheckError(
      'STATUS_LIST_LENGTH_ERROR',
      `status list holds ${bitLength(
        bits,
      )} entries, fewer than ${STATUS_LIST_SIZE}`,
    );
  }
  if (entry.statusListIndex >= bitLength(bits)) {
    throw new StatusListCheckError(
      'RANGE_ERROR',
      `statusListIndex ${entry.statusListIndex} is outside the list`,
    );
  }
  return isBitSet(bits, entry.statusListIndex);
}

function compactJwsOf(body: unknown): unknown {
  if (typeof body === 'string') {
    return body.startsWith(DATA_URL_VC_JWT_PREFIX)
      ? body.slice(DATA_URL_VC_JWT_PREFIX.length)
      : body;
  }
  if (!isPlainObject(body)) {
    return undefined;
  }
  if (
    typeof body.id === 'string' &&
    body.id.startsWith(DATA_URL_VC_JWT_PREFIX)
  ) {
    return body.id.slice(DATA_URL_VC_JWT_PREFIX.length);
  }
  return isPlainObject(body.proof) ? body.proof.jwt : undefined;
}

function isInValidityWindow(list: Record<string, unknown>, now: Date) {
  const validFrom =
    typeof list.validFrom === 'string' ? new Date(list.validFrom) : undefined;
  const validUntil =
    typeof list.validUntil === 'string' ? new Date(list.validUntil) : undefined;
  const started = validFrom === undefined || validFrom <= now;
  const notEnded = validUntil === undefined || now <= validUntil;
  return started && notEnded;
}

function asArray(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [value];
}

function isPrivateAddress(address: string): boolean {
  const patterns = isIP(address) === 6 ? PRIVATE_IPV6 : PRIVATE_IPV4;
  return patterns.some((pattern) => pattern.test(address));
}
