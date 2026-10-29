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
