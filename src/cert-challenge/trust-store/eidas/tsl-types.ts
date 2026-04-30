/**
 * ETSI TS 119 612 — Trusted List XML data types we actually consume.
 * Only the fields needed by our pipeline are modelled.
 */

export const TSL_NS = 'http://uri.etsi.org/02231/v2#';
export const ECC_NS = 'http://uri.etsi.org/02231/v2/additionaltypes#';
export const XADES_NS = 'http://uri.etsi.org/01903/v1.3.2#';
export const DS_NS = 'http://www.w3.org/2000/09/xmldsig#';

/** Parsed pointer to a member-state Trusted List, taken from the LOTL. */
export interface CountryTslPointer {
  /** ISO 3166-1 alpha-2 country code (`SI`, `DE`, ...) */
  country: string;
  /** Absolute URL to the country TL XML. */
  tslLocation: string;
  /**
   * SHA-256 fingerprints (lower-case hex) of the certificates announced as
   * the legitimate signers of this country's TL. Any other XAdES signing cert
   * MUST be rejected.
   */
  allowedSignerFingerprints: Set<string>;
}

export type ServiceStatus =
  | 'granted'
  | 'withdrawn'
  | 'revoked'
  | 'suspended'
  | 'undersupervision'
  | 'supervisionincessation'
  | 'supervisionceased'
  | 'supervisionrevoked'
  | 'accredited'
  | 'accreditationceased'
  | 'accreditationrevoked'
  | 'unknown';

/** A CA service entry from a per-country TL that we may turn into an anchor. */
export interface CaServiceEntry {
  country: string;
  serviceStatus: ServiceStatus;
  /** Raw URIs from `<AdditionalServiceInformation>/<URI>` for the service. */
  additionalServiceUris: string[];
  /** DER bytes of the CA certificate(s) announced for this service. */
  caCertsDer: Uint8Array[];
}

export const SVC_TYPE_CA_QC =
  'http://uri.etsi.org/TrstSvc/Svctype/CA/QC';

export const SVC_STATUS_GRANTED =
  'http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted';

export const ADD_INFO_FOR_ESIGNATURES =
  'http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/ForeSignatures';

export const ADD_INFO_FOR_ESEALS =
  'http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/ForeSeals';

export const ADD_INFO_FOR_WEB_AUTH =
  'http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/ForWebSiteAuthentication';
