import { BadRequestException, Injectable, Logger } from '@nestjs/common';
import { HttpService } from '@nestjs/axios';
import { firstValueFrom } from 'rxjs';
import { decodeBitstring, isBitSet } from 'src/status-list/bitstring';
import {
  STATUS_LIST_ENTRY_TYPE,
  STATUS_LIST_PURPOSE,
} from 'src/status-list/status-list.constants';
import { StatusListService } from 'src/status-list/status-list.service';
import {
  isPlainObject,
  leafCertificateOf,
  MalformedJwsError,
  parseCompactJws,
  ParsedJws,
  verifyJwsSignature,
} from './jws';
import {
  RevocationCheck,
  RevocationStatus,
  SignatureCheck,
  ValidityCheck,
  VerificationResult,
} from './verification.types';

/** Claims `jsonwebtoken` adds next to the credential; not part of the credential object. */
const JWT_REGISTERED_CLAIMS = ['iat', 'exp', 'nbf', 'iss', 'sub', 'aud', 'jti'];
const PROOF_KEY = 'proof';
const REMOTE_LIST_TIMEOUT_MS = 5_000;

type VerificationInput = {
  jws: ParsedJws;
  /** The credential object given next to the JWT, without its proof. */
  credential?: Record<string, unknown>;
};

type StatusListEntry = {
  statusListIndex: number;
  statusListCredential: string;
};

/**
 * Checks a verifiable credential the way a third party would: signature by
 * the `x5c` leaf, validity window, revocation through the status list the
 * credential points at. Nothing is stored and no caller identity is needed.
 */
@Injectable()
export class VerificationService {
  private readonly logger = new Logger(VerificationService.name);

  constructor(
    private readonly statusList: StatusListService,
    private readonly httpService: HttpService,
  ) {}

  async verify(body: unknown): Promise<VerificationResult> {
    const input = this.readInput(body);
    const credential = withoutJwtClaims(input.jws.payload);
    const now = new Date();

    const signature = this.checkSignature(input, credential);
    const validity = checkValidity(credential, now);
    const revocation = await this.checkRevocation(credential, now);

    return {
      valid:
        signature.valid && validity.valid && revocation.status !== 'revoked',
      checks: { signature, validity, revocation },
      credential,
    };
  }

  /** `{ jwt }` or `{ credential: { ..., proof: { jwt } } }`; anything else is a 400. */
  private readInput(body: unknown): VerificationInput {
    if (!isPlainObject(body)) {
      throw new BadRequestException('Body must be a JSON object.');
    }
    const credential = isPlainObject(body.credential)
      ? body.credential
      : undefined;
    const proof =
      credential && isPlainObject(credential.proof)
        ? credential.proof
        : undefined;
    const token = body.jwt ?? proof?.jwt;
    if (token === undefined) {
      throw new BadRequestException(
        'Provide "jwt" or a "credential" with "proof.jwt".',
      );
    }
    try {
      return {
        jws: parseCompactJws(token),
        credential: credential && withoutProof(credential),
      };
    } catch (error) {
      if (error instanceof MalformedJwsError) {
        throw new BadRequestException(error.message);
      }
      throw error;
    }
  }

  private checkSignature(
    input: VerificationInput,
    payloadCredential: Record<string, unknown>,
  ): SignatureCheck {
    const certificate = leafCertificateOf(input.jws.header);
    const matchesGivenCredential =
      !input.credential ||
      canonicalJson(input.credential) === canonicalJson(payloadCredential);
    return {
      valid:
        !!certificate &&
        matchesGivenCredential &&
        verifyJwsSignature(input.jws, certificate),
      issuerDid: issuerDidOf(payloadCredential),
      certificateSubject: certificate
        ? certificate.subject.split('\n').join(', ')
        : null,
    };
  }

  private async checkRevocation(
    credential: Record<string, unknown>,
    now: Date,
  ): Promise<RevocationCheck> {
    const entry = revocationEntryOf(credential.credentialStatus);
    return {
      status: await this.revocationStatus(entry),
      checkedAt: now.toISOString(),
    };
  }

  private async revocationStatus(
    entry: StatusListEntry | undefined,
  ): Promise<RevocationStatus> {
    if (!entry) {
      return 'unknown';
    }
    try {
      const revoked = await this.isRevoked(entry);
      return revoked ? 'revoked' : 'valid';
    } catch (error) {
      this.logger.warn(
        `status list ${entry.statusListCredential} unavailable: ${error.message}`,
      );
      return 'unknown';
    }
  }

  private async isRevoked(entry: StatusListEntry): Promise<boolean> {
    if (this.statusList.isLocalListUrl(entry.statusListCredential)) {
      return this.statusList.isRevoked(entry.statusListIndex);
    }
    const encodedList = await this.fetchRemoteEncodedList(
      entry.statusListCredential,
    );
    return isBitSet(decodeBitstring(encodedList), entry.statusListIndex);
  }

  private async fetchRemoteEncodedList(url: string): Promise<string> {
    const response = await firstValueFrom(
      this.httpService.get<unknown>(url, {
        headers: { Accept: 'application/json' },
        timeout: REMOTE_LIST_TIMEOUT_MS,
      }),
    );
    const list =
      typeof response.data === 'string'
        ? parseCompactJws(response.data).payload
        : response.data;
    const subject = isPlainObject(list) ? list.credentialSubject : undefined;
    const encodedList = isPlainObject(subject)
      ? subject.encodedList
      : undefined;
    if (typeof encodedList !== 'string') {
      throw new Error('response carries no credentialSubject.encodedList');
    }
    return encodedList;
  }
}

function checkValidity(
  credential: Record<string, unknown>,
  now: Date,
): ValidityCheck {
  const validFrom = parseDate(credential.validFrom);
  const validUntil = parseDate(credential.validUntil);
  const startsInTime = validFrom !== undefined && validFrom <= now;
  const notEnded = validUntil === undefined ? true : now <= validUntil;
  return {
    valid: startsInTime && notEnded,
    validFrom:
      typeof credential.validFrom === 'string' ? credential.validFrom : null,
    validUntil:
      typeof credential.validUntil === 'string' ? credential.validUntil : null,
  };
}

/** A date for a string claim: `undefined` when absent, an invalid Date when unparsable. */
function parseDate(claim: unknown): Date | undefined {
  return typeof claim === 'string' ? new Date(claim) : undefined;
}

/** The revocation entry of `credentialStatus` (a single entry or a list of them). */
function revocationEntryOf(
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
  const statusListIndex = Number(entry.statusListIndex);
  const statusListCredential = entry.statusListCredential;
  if (
    !Number.isInteger(statusListIndex) ||
    statusListIndex < 0 ||
    typeof statusListCredential !== 'string'
  ) {
    return undefined;
  }
  return { statusListIndex, statusListCredential };
}

function issuerDidOf(credential: Record<string, unknown>): string | null {
  const issuer = credential.issuer;
  if (typeof issuer === 'string') {
    return issuer;
  }
  return isPlainObject(issuer) && typeof issuer.id === 'string'
    ? issuer.id
    : null;
}

function withoutProof(
  credential: Record<string, unknown>,
): Record<string, unknown> {
  return withoutKeys(credential, [PROOF_KEY]);
}

function withoutJwtClaims(
  payload: Record<string, unknown>,
): Record<string, unknown> {
  return withoutKeys(payload, [...JWT_REGISTERED_CLAIMS, PROOF_KEY]);
}

function withoutKeys(
  object: Record<string, unknown>,
  keys: string[],
): Record<string, unknown> {
  return Object.fromEntries(
    Object.entries(object).filter(([key]) => !keys.includes(key)),
  );
}

/** JSON with object keys sorted at every level, so equal objects stringify equally. */
function canonicalJson(value: unknown): string {
  if (Array.isArray(value)) {
    return `[${value.map(canonicalJson).join(',')}]`;
  }
  if (isPlainObject(value)) {
    const entries = Object.keys(value)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`);
    return `{${entries.join(',')}}`;
  }
  return JSON.stringify(value);
}
