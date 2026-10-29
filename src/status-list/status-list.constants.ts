/** The single Bitstring Status List of this deployment. */
export const STATUS_LIST_ID = 1;
/** Entries per list; also the minimum a verifier accepts (W3C Bitstring Status List §2.2). */
export const STATUS_LIST_SIZE = 131_072;
export const STATUS_LIST_PURPOSE = 'revocation';
export const STATUS_LIST_ENTRY_TYPE = 'BitstringStatusListEntry';
export const STATUS_LIST_SUBJECT_TYPE = 'BitstringStatusList';
export const STATUS_LIST_CREDENTIAL_TYPE = 'BitstringStatusListCredential';
/** Every index ever handed out, so none is reused (§6.7); indices are drawn at random (§6.5). */
export const STATUS_LIST_SLOT_TABLE = 'credential_status_list_slot';
/** Random draws before falling back to a scan for a free index. */
export const STATUS_LIST_ALLOCATION_ATTEMPTS = 16;
/** Share of used indices above which allocations log a warning. */
export const STATUS_LIST_CAPACITY_WARNING_RATIO = 0.9;
/** The list is rebuilt from the database at most this often; also its `ttl` for verifiers. */
export const STATUS_LIST_CACHE_TTL_MS = 60_000;
/** `validUntil` of a served list, counted from the moment it is built. */
export const STATUS_LIST_VALIDITY_MS = 24 * 60 * 60 * 1000;
export const STATUS_LIST_PATH = '/v1/status-lists';
export const VC_JWT_MEDIA_TYPE = 'application/vc+jwt';
/** JOSE `typ` of a credential secured as a compact JWS (VC-JOSE-COSE). */
export const VC_JWT_TYP = 'vc+jwt';
