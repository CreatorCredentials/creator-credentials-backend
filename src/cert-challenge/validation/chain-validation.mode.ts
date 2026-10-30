/**
 * Controls what `CertValidatorService` does while the eIDAS trust store has
 * no anchors yet.
 *
 * - `enforce` (default): fail closed — submissions get a 503 until the store
 *   is loaded. This is the only acceptable mode on shared environments.
 * - `skip`: accept the leaf without the chain check. Local development only;
 *   it is announced with a warning at boot and on every skipped validation.
 */
export type ChainValidationMode = 'enforce' | 'skip';

export const CHAIN_VALIDATION_MODE = 'CHAIN_VALIDATION_MODE';

export const CHAIN_VALIDATION_ENV = 'EIDAS_CHAIN_VALIDATION';

const DEFAULT_MODE: ChainValidationMode = 'enforce';

export function chainValidationModeFromEnv(
  env: NodeJS.ProcessEnv = process.env,
): ChainValidationMode {
  const raw = env[CHAIN_VALIDATION_ENV]?.trim().toLowerCase();
  if (raw === undefined || raw === '') return DEFAULT_MODE;
  if (raw === 'enforce' || raw === 'skip') return raw;
  throw new Error(
    `${CHAIN_VALIDATION_ENV} must be "enforce" or "skip", got "${raw}"`,
  );
}
