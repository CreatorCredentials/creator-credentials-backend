import { gunzipSync } from 'zlib';
import { decodeBitstring, encodeBitstring, isBitSet } from './bitstring';
import { STATUS_LIST_SIZE } from './status-list.constants';

describe('bitstring encoding', () => {
  it('encodes 131 072 bits as multibase base64url GZIP', () => {
    const encoded = encodeBitstring([]);

    expect(encoded.startsWith('u')).toBe(true);
    expect(encoded).not.toMatch(/[+/=]/);
    const bits = gunzipSync(Buffer.from(encoded.slice(1), 'base64url'));
    expect(bits.length * 8).toBe(STATUS_LIST_SIZE);
    expect(bits.every((byte) => byte === 0)).toBe(true);
  });

  it('round-trips the set indices and leaves every other bit clear', () => {
    const revoked = [0, 7, 8, 9, 1000, STATUS_LIST_SIZE - 1];

    const bits = decodeBitstring(encodeBitstring(revoked));

    for (const index of revoked) {
      expect(isBitSet(bits, index)).toBe(true);
    }
    const setCount = [...bits].reduce(
      (count, byte) => count + byte.toString(2).replace(/0/g, '').length,
      0,
    );
    expect(setCount).toBe(revoked.length);
  });

  it('places index 0 in the most significant bit of the first byte', () => {
    const bits = decodeBitstring(encodeBitstring([0, 15]));

    expect(bits[0]).toBe(0b1000_0000);
    expect(bits[1]).toBe(0b0000_0001);
  });

  it('rejects an index outside the list', () => {
    expect(() => encodeBitstring([STATUS_LIST_SIZE])).toThrow(RangeError);
    expect(() => encodeBitstring([-1])).toThrow(RangeError);
    expect(() => isBitSet(Buffer.alloc(1), 8)).toThrow(RangeError);
  });

  it('rejects an encodedList that is not multibase base64url', () => {
    expect(() => decodeBitstring('zabc')).toThrow(RangeError);
  });
});
