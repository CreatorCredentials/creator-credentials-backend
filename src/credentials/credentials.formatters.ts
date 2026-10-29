import {
  AdminCredential,
  ConnectCredential,
  CreatorCredential,
  DataSupplierCredential,
  LicciumDataSupplierCredential,
  DidWebCredential,
  DomainCredential,
  EmailCredential,
  ExternalKeypairVerificationCredential,
  IssuedCredential,
  IssuedCredentialCreator,
  MembershipCredential,
  RevocationFields,
  VerifiedCredentialsUnion,
  WalletCredential,
} from 'src/shared/typings/Credentials';
import { Credential } from './credential.entity';
import { CredentialType } from 'src/shared/typings/CredentialType';
import { CredentialVerificationStatus } from 'src/shared/typings/CredentialVerificationStatus';
import { NotFoundException } from '@nestjs/common';
import { User } from 'src/users/user.entity';
import { findVerifiedEmail } from 'src/users/verified-email';
import {
  Connection,
  ConnectionStatus,
} from 'src/connections/connection.entity';

const DEFAUTL_COMPANY_NAME = 'Liccium B.V.';
const TRANSIENT_FIELD_PREFIX = '__';

export function formatCredentialForUnion(
  credential: Credential,
): VerifiedCredentialsUnion {
  switch (credential.credentialType) {
    case CredentialType.EMail:
      return formatEmailCredential(credential);
    case CredentialType.DidWeb:
      return formatDidWebCredential(credential);
    case CredentialType.Wallet:
      return formatWalletCredential(credential);
    case CredentialType.Domain:
      return formatDomainCredential(credential);
    case CredentialType.Member:
      return formatMemberCredential(credential);
    case CredentialType.DataSupplier:
      return formatDataSupplierCredential(credential);
    case CredentialType.LicciumDataSupplier:
      return formatLicciumDataSupplierCredential(credential);
    case CredentialType.Connect:
      return formatConnectCredential(credential);
    case CredentialType.ExternalKeypairVerification:
      return formatExternalKeypairVerificationCredential(credential);
    case CredentialType.Creator:
      return formatCreatorCredential(credential);
    default:
      throw new NotFoundException(
        'CredentialType is not defined properly for credential.',
      );
  }
}

/**
 * Shape of GET credentials/issuers. Expects `user`, `user.credentials` and
 * `user.createdConnections` to be loaded on the credential.
 */
export function formatIssuedCredential(
  credential: Credential,
): IssuedCredential {
  return {
    ...formatCredentialForUnion(credential),
    issuedAt: credential.createdAt,
    updatedAt: credential.updatedAt,
    revokedAt: credential.revokedAt ?? null,
    revokedReason: credential.revokedReason ?? null,
    connectionStatus: findConnectionStatus(
      credential.user,
      credential.issuerId,
    ),
    creator: formatCreatorIdentity(credential.user),
  };
}

/**
 * Shape of the admin routes. Expects what `formatIssuedCredential` expects
 * plus `issuer` and `revokedBy`; `statusListCredentialUrl` is the URL of the
 * platform's status list.
 */
export function formatAdminCredential(
  credential: Credential,
  statusListCredentialUrl: string,
): AdminCredential {
  return {
    ...formatIssuedCredential(credential),
    issuer: credential.issuer
      ? {
          id: credential.issuer.id,
          name: credential.issuer.name ?? null,
          domain: credential.issuer.domain ?? null,
        }
      : null,
    revokedBy: credential.revokedBy
      ? {
          id: credential.revokedBy.id,
          name: credential.revokedBy.name ?? null,
          role: credential.revokedBy.clerkRole,
        }
      : null,
    statusList:
      credential.statusListIndex == null
        ? null
        : {
            credential: statusListCredentialUrl,
            index: credential.statusListIndex,
          },
  };
}

/**
 * The one issued (SUCCESS) credential of a single-row type, formatted;
 * `undefined` when the user has none.
 */
export function formatSingleSuccessCredential(
  credentials: Credential[],
): VerifiedCredentialsUnion | undefined {
  const issued = credentials.find(
    (credential) =>
      credential.credentialStatus === CredentialVerificationStatus.Success,
  );
  return issued && formatCredentialForUnion(issued);
}

/**
 * Removes the server-side bookkeeping keys of a credential object
 * (`__keypairSnapshot`, `__acceptanceChallenge`, ...) that must never leave
 * the API.
 */
export function stripTransientFields<T extends object>(
  credentialObject: T,
): Partial<T> {
  return Object.fromEntries(
    Object.entries(credentialObject ?? {}).filter(
      ([key]) => !key.startsWith(TRANSIENT_FIELD_PREFIX),
    ),
  ) as Partial<T>;
}

export function formatEmailCredential(credential: Credential): EmailCredential {
  return {
    id: credential.id.toString(),
    status: credential.credentialStatus,
    type: CredentialType.EMail,
    data: {
      address: credential.email || 'wrong',
      companyName: DEFAUTL_COMPANY_NAME,
      requirements: 'Info about requirements',
      userId: credential.userId,
      credentialObject: credentialObjectWithProof(credential),
    },
  };
}

export function formatWalletCredential(
  credential: Credential,
): WalletCredential {
  return {
    id: credential.id.toString(),
    status: credential.credentialStatus,
    type: CredentialType.Wallet,
    data: {
      address: credential.email || 'wrong',
      companyName: DEFAUTL_COMPANY_NAME,
      requirements: 'Info about requirements',
      userId: credential.userId,
      credentialObject: credentialObjectWithProof(credential),
    },
  };
}

export function formatDomainCredential(
  credential: Credential,
): DomainCredential {
  return {
    id: credential.id.toString(),
    status: credential.credentialStatus,
    type: CredentialType.Domain,
    data: {
      domain: credential.email || 'wrong',
      companyName: DEFAUTL_COMPANY_NAME,
      requirements: 'Info about requirements',
      userId: credential.userId,
      credentialObject: credentialObjectWithProof(credential),
    },
  };
}

export function formatDidWebCredential(
  credential: Credential,
): DidWebCredential {
  return {
    id: credential.id.toString(),
    status: credential.credentialStatus,
    type: CredentialType.DidWeb,
    data: {
      domain: credential.email || 'wrong',
      companyName: DEFAUTL_COMPANY_NAME,
      requirements: 'Info about requirements',
      userId: credential.userId,
      credentialObject: credentialObjectWithProof(credential),
    },
  };
}

export function formatMemberCredential(
  credential: Credential,
): MembershipCredential {
  return {
    id: credential.id.toString(),
    status: credential.credentialStatus,
    type: CredentialType.Member,
    ...revocationFields(credential),
    data: {
      validity: credential.value || 'wrong',
      companyName: credential?.issuer?.name || DEFAUTL_COMPANY_NAME,
      requirements: 'Info about requirements',
      userId: credential.userId,
      credentialObject: credentialObjectWithProof(credential),
    },
  };
}

export function formatDataSupplierCredential(
  credential: Credential,
): DataSupplierCredential {
  return {
    id: credential.id.toString(),
    status: credential.credentialStatus,
    type: CredentialType.DataSupplier,
    ...revocationFields(credential),
    data: {
      validity: credential.value || 'wrong',
      companyName: credential?.issuer?.name || DEFAUTL_COMPANY_NAME,
      requirements: 'Info about requirements',
      userId: credential.userId,
      credentialObject: credentialObjectWithProof(credential),
    },
  };
}

export function formatLicciumDataSupplierCredential(
  credential: Credential,
): LicciumDataSupplierCredential {
  return {
    id: credential.id.toString(),
    status: credential.credentialStatus,
    type: CredentialType.LicciumDataSupplier,
    ...revocationFields(credential),
    data: {
      validity: credential.value || 'wrong',
      companyName: credential?.issuer?.name || DEFAUTL_COMPANY_NAME,
      requirements: 'Info about requirements',
      userId: credential.userId,
      credentialObject: credentialObjectWithProof(credential),
    },
  };
}

export function formatConnectCredential(
  credential: Credential,
): ConnectCredential {
  return {
    id: credential.id.toString(),
    status: credential.credentialStatus,
    type: CredentialType.Connect,
    data: {
      validity: credential.value || 'wrong',
      companyName: DEFAUTL_COMPANY_NAME,
      requirements: 'Info about requirements',
      userId: credential.userId,
      credentialObject: credentialObjectWithProof(credential),
    },
  };
}

export function formatExternalKeypairVerificationCredential(
  credential: Credential,
): ExternalKeypairVerificationCredential {
  return {
    id: credential.id.toString(),
    status: credential.credentialStatus,
    type: CredentialType.ExternalKeypairVerification,
    data: {
      sameAs: credential.value || undefined,
      requirements: 'Platform-issued keypair ownership proof',
      userId: credential.userId,
      credentialObject: credentialObjectWithProof(credential),
    },
  };
}

export function formatCreatorCredential(
  credential: Credential,
): CreatorCredential {
  return {
    id: credential.id.toString(),
    status: credential.credentialStatus,
    type: CredentialType.Creator,
    data: {
      verifiedBy: credential.value,
      credentialObject: credentialObjectWithProof(credential),
    },
  };
}

function credentialObjectWithProof(credential: Credential) {
  return {
    proof: {
      type: 'JwtProof2020',
      jwt: credential.token,
    },
    ...stripTransientFields(credential.credentialObject),
  };
}

function revocationFields(credential: Credential): RevocationFields {
  if (!credential.revokedAt) {
    return {};
  }
  return {
    revokedAt: credential.revokedAt,
    ...(credential.revokedReason
      ? { revokedReason: credential.revokedReason }
      : {}),
  };
}

function formatCreatorIdentity(creator: User): IssuedCredentialCreator {
  return {
    id: creator.id,
    name: creator.name ?? null,
    email: findVerifiedEmail(creator) ?? null,
    didKey: creator.didKey,
  };
}

/**
 * Status of the latest connection between creator and issuer; a pair can
 * have several rows once a connection was rejected or revoked.
 */
function findConnectionStatus(
  creator: User,
  issuerId: number,
): ConnectionStatus | null {
  const latest = (creator.createdConnections ?? [])
    .filter((connection) => connection.issuerId === issuerId)
    .reduce<Connection | undefined>(
      (newest, connection) =>
        !newest || connection.id > newest.id ? connection : newest,
      undefined,
    );
  return latest?.status ?? null;
}
