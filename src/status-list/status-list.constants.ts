/** The single Bitstring Status List of this deployment. */
export const STATUS_LIST_ID = 1;
export const STATUS_LIST_SIZE = 131_072;
export const STATUS_LIST_PURPOSE = 'revocation';
export const STATUS_LIST_ENTRY_TYPE = 'BitstringStatusListEntry';
export const STATUS_LIST_SUBJECT_TYPE = 'BitstringStatusList';
export const STATUS_LIST_CREDENTIAL_TYPE = 'BitstringStatusListCredential';
export const STATUS_LIST_SEQUENCE = 'credential_status_list_index_seq';
/** The list is rebuilt from the database at most this often. */
export const STATUS_LIST_CACHE_TTL_MS = 60_000;
/** `validUntil` of a served list, counted from the moment it is built. */
export const STATUS_LIST_VALIDITY_MS = 24 * 60 * 60 * 1000;
export const STATUS_LIST_PATH = '/v1/status-lists';
export const VC_JWT_MEDIA_TYPE = 'application/vc+jwt';
