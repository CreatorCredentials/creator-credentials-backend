import {
  STATUS_LIST_ENTRY_TYPE,
  STATUS_LIST_PURPOSE,
} from './status-list.constants';

/** The `credentialStatus` entry a verifiable credential carries (W3C Bitstring Status List v1.0). */
export type CredentialStatusEntry = {
  id: string;
  type: typeof STATUS_LIST_ENTRY_TYPE;
  statusPurpose: typeof STATUS_LIST_PURPOSE;
  statusListIndex: string;
  statusListCredential: string;
};

/** An index reserved for a credential together with the entry to embed before signing. */
export type ReservedStatusListEntry = {
  index: number;
  credentialStatus: CredentialStatusEntry;
};

export type StatusListCredential = {
  /** The BitstringStatusListCredential with `proof.jwt`, as served as JSON. */
  credential: Record<string, unknown>;
  /** The same credential as a compact JWS. */
  jwt: string;
};

/** One entry of the registry of revoked credentials without a status entry. */
export type RevokedCredentialRecord = {
  /** The credential's own `id` (`urn:uuid:…`). */
  id: string;
  issuer: string | null;
  revokedAt: string | null;
};

export type RevokedCredentialsRegistry = {
  /** The registry document with `proof.jwt`, as served as JSON. */
  registry: Record<string, unknown>;
  /** The same document as a compact JWS. */
  jwt: string;
};
