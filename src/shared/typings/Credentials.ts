import { CredentialType } from './CredentialType';
import { CredentialVerificationStatus } from './CredentialVerificationStatus';
import { ConnectionStatus } from 'src/connections/connection.entity';
import { ClerkRole } from 'src/users/user.entity';

/** Present on revoked credentials only; `revokedReason` only when the issuer gave one. */
export type RevocationFields = {
  revokedAt?: Date;
  revokedReason?: string;
};

type BaseCredential<
  T extends CredentialType,
  D extends object,
> = RevocationFields & {
  id: string;
  status?: CredentialVerificationStatus;
  type: T;
  data: D;
};

export type EmailCredential = BaseCredential<
  CredentialType.EMail,
  {
    address: string;
    requirements?: string;
    companyName?: string;
    userId?: number;
    // eslint-disable-next-line
    credentialObject?: any;
  }
>;

export type WalletCredential = BaseCredential<
  CredentialType.Wallet,
  {
    address: string;
    companyName?: string;
    requirements?: string;
    userId?: number;
    // eslint-disable-next-line
    credentialObject?: any;
  }
>;

export type DomainCredential = BaseCredential<
  CredentialType.Domain,
  {
    domain: string;
    companyName?: string;
    requirements?: string;
    userId?: number;
    // eslint-disable-next-line
    credentialObject?: any;
  }
>;

export type MembershipCredential = BaseCredential<
  CredentialType.Member,
  {
    companyName?: string;
    requirements?: string;
    validity?: string;
    userId?: number;
    // eslint-disable-next-line
    credentialObject?: any;
  }
>;

export type DataSupplierCredential = BaseCredential<
  CredentialType.DataSupplier,
  {
    companyName?: string;
    requirements?: string;
    validity?: string;
    userId?: number;
    // eslint-disable-next-line
    credentialObject?: any;
  }
>;

export type LicciumDataSupplierCredential = BaseCredential<
  CredentialType.LicciumDataSupplier,
  {
    companyName?: string;
    requirements?: string;
    validity?: string;
    userId?: number;
    // eslint-disable-next-line
    credentialObject?: any;
  }
>;

export type ConnectCredential = BaseCredential<
  CredentialType.Connect,
  {
    companyName?: string;
    requirements?: string;
    validity?: string;
    userId?: number;
    // eslint-disable-next-line
    credentialObject?: any;
  }
>;

export type DidWebCredential = BaseCredential<
  CredentialType.DidWeb,
  {
    domain: string;
    companyName?: string;
    requirements?: string;
    userId?: number;
    // eslint-disable-next-line
    credentialObject?: any;
  }
>;

export type ExternalKeypairVerificationCredential = BaseCredential<
  CredentialType.ExternalKeypairVerification,
  {
    sameAs?: string;
    requirements?: string;
    userId?: number;
    // eslint-disable-next-line
    credentialObject?: any;
  }
>;

export type CreatorCredential = BaseCredential<
  CredentialType.Creator,
  {
    verifiedBy: string;
    // eslint-disable-next-line
    credentialObject?: any;
  }
>;

export type VerifiedCredentialsUnion =
  | EmailCredential
  | WalletCredential
  | DomainCredential
  | MembershipCredential
  | DataSupplierCredential
  | LicciumDataSupplierCredential
  | ConnectCredential
  | DidWebCredential
  | ExternalKeypairVerificationCredential
  | CreatorCredential;

export type CreatorCredentials = {
  email: EmailCredential;
  metaMask: WalletCredential | null;
  domain: DomainCredential | null;
  connect: ConnectCredential | null;
  membership: MembershipCredential[];
  keypairVerifications: ExternalKeypairVerificationCredential[];
};

export type IssuerCredentials = {
  domain: DomainCredential;
  didWeb: DidWebCredential;
  membership: MembershipCredential[];
};

export type IssuedCredentialCreator = {
  id: number;
  name: string | null;
  email: string | null;
  didKey: string;
};

/**
 * Item of GET credentials/issuers: the union shape plus timestamps, the
 * revocation fields and the creator identity the issued-credentials page renders.
 */
export type IssuedCredential = VerifiedCredentialsUnion & {
  issuedAt: Date;
  updatedAt: Date;
  revokedAt: Date | null;
  revokedReason: string | null;
  connectionStatus: ConnectionStatus | null;
  creator: IssuedCredentialCreator;
};

export type AdminCredentialIssuer = {
  id: number;
  name: string | null;
  domain: string | null;
};

export type AdminCredentialRevoker = {
  id: number;
  name: string | null;
  role: ClerkRole;
};

/** Where the credential lives in the platform's Bitstring Status List. */
export type StatusListReference = {
  credential: string;
  index: number;
};

/**
 * Item of GET admin/credentials: the issued shape plus the issuer (null for a
 * self-issued credential), who revoked it and its status-list entry (null
 * for credentials issued before the list existed).
 */
export type AdminCredential = IssuedCredential & {
  issuer: AdminCredentialIssuer | null;
  revokedBy: AdminCredentialRevoker | null;
  statusList: StatusListReference | null;
};
