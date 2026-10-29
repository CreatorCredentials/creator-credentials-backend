export type RevocationStatus = 'valid' | 'revoked' | 'unknown';

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
