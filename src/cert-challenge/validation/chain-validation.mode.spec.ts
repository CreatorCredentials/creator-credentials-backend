import { chainValidationModeFromEnv } from './chain-validation.mode';

describe('chainValidationModeFromEnv', () => {
  it('enforces by default', () => {
    expect(chainValidationModeFromEnv({})).toBe('enforce');
    expect(chainValidationModeFromEnv({ EIDAS_CHAIN_VALIDATION: '' })).toBe(
      'enforce',
    );
  });

  it('accepts both modes regardless of case', () => {
    expect(chainValidationModeFromEnv({ EIDAS_CHAIN_VALIDATION: 'skip' })).toBe(
      'skip',
    );
    expect(
      chainValidationModeFromEnv({ EIDAS_CHAIN_VALIDATION: ' Enforce ' }),
    ).toBe('enforce');
  });

  it('rejects anything else so a typo cannot silently disable the check', () => {
    expect(() =>
      chainValidationModeFromEnv({ EIDAS_CHAIN_VALIDATION: 'off' }),
    ).toThrow(/must be "enforce" or "skip"/);
  });
});
