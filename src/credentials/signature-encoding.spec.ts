import * as crypto from 'crypto';
import { normalizeEcdsaSignature } from './signature-encoding';

const RAW_SIGNATURE_LENGTH = 64;

function derInteger(value: Buffer): Buffer {
  const needsSignByte = (value[0] & 0x80) !== 0;
  const body = needsSignByte ? Buffer.concat([Buffer.from([0]), value]) : value;
  return Buffer.concat([Buffer.from([0x02, body.length]), body]);
}

function derSequence(...integers: Buffer[]): Buffer {
  const body = Buffer.concat(integers);
  return Buffer.concat([Buffer.from([0x30, body.length]), body]);
}

describe('normalizeEcdsaSignature', () => {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', {
    namedCurve: 'P-256',
  });
  const signingInput = Buffer.from('header.payload');

  it('converts the DER signature openssl emits into raw r||s accepted by JOSE verifiers', () => {
    const derSignature = crypto.sign('sha256', signingInput, privateKey);

    const rawSignature = normalizeEcdsaSignature(derSignature);

    expect(rawSignature).toHaveLength(RAW_SIGNATURE_LENGTH);
    expect(
      crypto.verify(
        'sha256',
        signingInput,
        { key: publicKey, dsaEncoding: 'ieee-p1363' },
        rawSignature,
      ),
    ).toBe(true);
  });

  it('returns a raw signature unchanged', () => {
    const rawSignature = crypto.sign('sha256', signingInput, {
      key: privateKey,
      dsaEncoding: 'ieee-p1363',
    });

    expect(normalizeEcdsaSignature(rawSignature)).toEqual(rawSignature);
  });

  it('pads short components and drops the DER sign byte', () => {
    const r = Buffer.from([0x01]);
    const s = Buffer.alloc(32, 0xff);

    const rawSignature = normalizeEcdsaSignature(
      derSequence(derInteger(r), derInteger(s)),
    );

    expect(rawSignature).toEqual(Buffer.concat([Buffer.alloc(31), r, s]));
  });

  it('rejects a component longer than the curve allows', () => {
    const tooLong = Buffer.alloc(33, 0x7f);
    const derSignature = derSequence(
      derInteger(tooLong),
      derInteger(Buffer.from([0x01])),
    );

    expect(() => normalizeEcdsaSignature(derSignature)).toThrow(RangeError);
  });
});
