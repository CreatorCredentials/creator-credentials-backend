import { gunzipSync, gzipSync } from 'zlib';
import { STATUS_LIST_SIZE } from './status-list.constants';

const MULTIBASE_BASE64URL_PREFIX = 'u';
const BITS_PER_BYTE = 8;
/** Bit 0 of a byte is its most significant bit (left-to-right, as the W3C bitstring is read). */
const FIRST_BIT_MASK = 0b1000_0000;
/** Upper bound for an expanded list; a genuine list of millions of entries stays far below it. */
const MAX_EXPANDED_BYTES = 16 * 1024 * 1024;

/**
 * Builds the `encodedList` of a Bitstring Status List: a bitstring of
 * `size` bits with a `1` at every given index, GZIP-compressed and
 * multibase base64url encoded (prefix `u`, no padding).
 */
export function encodeBitstring(
  setIndices: Iterable<number>,
  size = STATUS_LIST_SIZE,
): string {
  const bits = Buffer.alloc(size / BITS_PER_BYTE);
  for (const index of setIndices) {
    assertIndexInRange(index, size);
    bits[byteOffset(index)] |= bitMask(index);
  }
  return MULTIBASE_BASE64URL_PREFIX + gzipSync(bits).toString('base64url');
}

/** Inverse of `encodeBitstring`: the raw bitstring bytes (expansion, §3.4). */
export function decodeBitstring(encodedList: string): Buffer {
  if (!encodedList.startsWith(MULTIBASE_BASE64URL_PREFIX)) {
    throw new RangeError(
      `encodedList must be multibase base64url (prefix "${MULTIBASE_BASE64URL_PREFIX}")`,
    );
  }
  return gunzipSync(Buffer.from(encodedList.slice(1), 'base64url'), {
    maxOutputLength: MAX_EXPANDED_BYTES,
  });
}

export function bitLength(bits: Buffer): number {
  return bits.length * BITS_PER_BYTE;
}

export function isBitSet(bits: Buffer, index: number): boolean {
  assertIndexInRange(index, bitLength(bits));
  return (bits[byteOffset(index)] & bitMask(index)) !== 0;
}

function byteOffset(index: number): number {
  return Math.floor(index / BITS_PER_BYTE);
}

function bitMask(index: number): number {
  return FIRST_BIT_MASK >> index % BITS_PER_BYTE;
}

function assertIndexInRange(index: number, size: number): void {
  if (!Number.isInteger(index) || index < 0 || index >= size) {
    throw new RangeError(
      `status list index ${index} is outside 0..${size - 1}`,
    );
  }
}
