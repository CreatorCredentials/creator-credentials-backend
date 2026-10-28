const DER_SEQUENCE_TAG = 0x30;
const DER_INTEGER_TAG = 0x02;
const DER_HEADER_LENGTH = 2;

/**
 * Returns an ECDSA signature in the raw `r || s` form a JWS `ES256` signature
 * requires. `openssl dgst -sign` emits the DER form (a SEQUENCE of two
 * INTEGERs); that form is converted, anything else is returned unchanged.
 * Only short-form DER lengths are handled, which covers every signature
 * shorter than 128 bytes (P-256 included).
 */
export function normalizeEcdsaSignature(
  signature: Buffer,
  componentLength = 32,
): Buffer {
  const components = readDerIntegerPair(signature);
  if (!components) {
    return signature;
  }
  return Buffer.concat(
    components.map((component) => fitComponent(component, componentLength)),
  );
}

function readDerIntegerPair(buffer: Buffer): [Buffer, Buffer] | undefined {
  const isSequence =
    buffer.length > DER_HEADER_LENGTH &&
    buffer[0] === DER_SEQUENCE_TAG &&
    buffer[1] === buffer.length - DER_HEADER_LENGTH;
  if (!isSequence) {
    return undefined;
  }
  const first = readDerInteger(buffer, DER_HEADER_LENGTH);
  const second = first && readDerInteger(buffer, first.end);
  if (!second || second.end !== buffer.length) {
    return undefined;
  }
  return [first.value, second.value];
}

function readDerInteger(
  buffer: Buffer,
  offset: number,
): { value: Buffer; end: number } | undefined {
  const hasHeader =
    offset + DER_HEADER_LENGTH <= buffer.length &&
    buffer[offset] === DER_INTEGER_TAG;
  if (!hasHeader) {
    return undefined;
  }
  const start = offset + DER_HEADER_LENGTH;
  const end = start + buffer[offset + 1];
  if (end > buffer.length) {
    return undefined;
  }
  return { value: buffer.subarray(start, end), end };
}

/**
 * Drops the DER sign byte and left-pads with zeros to the fixed component
 * length of the curve.
 */
function fitComponent(component: Buffer, length: number): Buffer {
  const significant = stripLeadingZeros(component);
  if (significant.length > length) {
    throw new RangeError(
      `ECDSA signature component has ${significant.length} bytes, at most ${length} expected`,
    );
  }
  return Buffer.concat([
    Buffer.alloc(length - significant.length),
    significant,
  ]);
}

function stripLeadingZeros(bytes: Buffer): Buffer {
  let start = 0;
  while (start < bytes.length - 1 && bytes[start] === 0) {
    start += 1;
  }
  return bytes.subarray(start);
}
