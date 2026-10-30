import { LotlPivotBootstrap } from './pivot-bootstrap';

/** SHA-256 of the EU Commission LOTL signer shipped in certificates/eidas/lotl-signers (valid to 2027-11-17). */
const EU_LOTL_SIGNER_2023_11 =
  'e0a620fbb6747362bb933ac44169d676a55344471 6cf5f31605f12a22b8396b1'.replace(
    / /g,
    '',
  );

describe('LotlPivotBootstrap', () => {
  afterEach(() => {
    delete process.env.EIDAS_LOTL_SIGNERS_DIR;
  });

  it('loads the shipped LOTL signer from the repository default directory', async () => {
    const fingerprints =
      await new LotlPivotBootstrap().loadAllowedSignerFingerprints();

    expect(fingerprints.has(EU_LOTL_SIGNER_2023_11)).toBe(true);
  });

  it('fails loudly when the directory is missing', async () => {
    process.env.EIDAS_LOTL_SIGNERS_DIR = '/nonexistent/lotl-signers';

    await expect(
      new LotlPivotBootstrap().loadAllowedSignerFingerprints(),
    ).rejects.toThrow(/cannot be read/);
  });
});
