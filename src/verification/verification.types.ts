/**
 * `valid` / `revoked`: answered from the `source`. `unknown`: the credential
 * carries no revocation entry (issued before status lists) and the platform
 * has no record of it, so nothing could be checked. `error`: it carries an
 * entry but the check failed; `reason` says why, in the terms of W3C
 * Bitstring Status List §3.2.
 */
export type RevocationStatus = 'valid' | 'revoked' | 'unknown' | 'error';

/**
 * `status-list`: the Bitstring Status List the credential points at.
 * `platform-record`: the platform's own record of a credential it issued
 * without a status entry; only this platform can answer for those.
 */
export type RevocationSource = 'status-list' | 'platform-record';

export type RevocationErrorReason =
  | 'MALFORMED_VALUE_ERROR'
  | 'STATUS_RETRIEVAL_ERROR'
  | 'STATUS_VERIFICATION_ERROR'
  | 'STATUS_LIST_LENGTH_ERROR'
  | 'RANGE_ERROR'
  | 'UNSUPPORTED_STATUS_SIZE';

export type SignatureCheck = {
  valid: boolean;
  issuerDid: string | null;
  certificateSubject: string | null;
};

export type ValidityCheck = {
  valid: boolean;
  validFrom: string | null;
  validUntil: string | null;
};

export type RevocationCheck = {
  status: RevocationStatus;
  checkedAt: string;
  source?: RevocationSource;
  reason?: RevocationErrorReason;
};

/** Response of POST credentials/verify. */
export type VerificationResult = {
  valid: boolean;
  checks: {
    signature: SignatureCheck;
    validity: ValidityCheck;
    revocation: RevocationCheck;
  };
  credential: Record<string, unknown>;
};
