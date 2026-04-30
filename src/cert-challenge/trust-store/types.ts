import type { X509Certificate } from '@peculiar/x509';

/**
 * A trusted CA certificate extracted from an eIDAS Trusted List.
 * Trust anchors come exclusively from member-state TLs whose XAdES signature
 * has been verified against the signing cert announced in the EU LOTL.
 */
export interface TrustAnchor {
  /** SHA-256 fingerprint of the cert's DER, lower-case hex, no separators. */
  fingerprint: string;
  /** Distinguished Name (RFC 4514) of the certificate subject. */
  subject: string;
  /** Distinguished Name of the certificate issuer. */
  issuer: string;
  /** ISO 3166-1 alpha-2 code of the member state whose TL declared this anchor. */
  country: string;
  /** Service types under which this CA was listed (filtered to QSeal/QSig). */
  serviceTypes: TrustedServiceType[];
  /** Parsed certificate. */
  certificate: X509Certificate;
  /** Raw DER bytes of the certificate (kept for fast re-export and hashing). */
  der: Uint8Array;
}

export type TrustedServiceType = 'QSeal' | 'QSig';

export type TrustStoreState =
  | { status: 'pending' }
  | { status: 'ready'; loadedAt: Date; anchorCount: number }
  | { status: 'error'; loadedAt: Date | null; error: string };
