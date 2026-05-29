import { createHash } from 'crypto';
import * as xpath from 'xpath';
import {
  CaServiceEntry,
  CountryTslPointer,
  DS_NS,
  ECC_NS,
  ServiceStatus,
  SVC_STATUS_GRANTED,
  SVC_TYPE_CA_QC,
  TSL_NS,
} from './tsl-types';

const select = xpath.useNamespaces({ tsl: TSL_NS, ds: DS_NS, ecc: ECC_NS });

/**
 * Extract every `OtherTSLPointer` of MIME type `application/vnd.etsi.tsl+xml`
 * from a validated EU LOTL DOM. Returns one `CountryTslPointer` per country.
 *
 * We deliberately ignore pointers that are not country TLs (e.g. pivot LOTLs
 * or other meta-pointers).
 */
export function parseLotlCountryPointers(doc: Document): CountryTslPointer[] {
  const pointers = select(
    '//tsl:PointersToOtherTSL/tsl:OtherTSLPointer',
    doc,
  ) as Node[];

  const result: CountryTslPointer[] = [];

  for (const pointer of pointers) {
    // MimeType lives in the ETSI "additionaltypes" namespace; SchemeTerritory
    // and TSLLocation are in the main TSL namespace.
    const mimeType = textOf(
      select(
        './/tsl:AdditionalInformation/tsl:OtherInformation/ecc:MimeType',
        pointer,
      ),
    );
    if (mimeType !== 'application/vnd.etsi.tsl+xml') continue;

    const tslLocation = textOf(
      select('./tsl:TSLLocation', pointer),
    );
    if (!tslLocation) continue;

    const country = textOf(
      select(
        './/tsl:AdditionalInformation/tsl:OtherInformation/tsl:SchemeTerritory',
        pointer,
      ),
    );
    if (!country) continue;

    const certNodes = select(
      './/tsl:ServiceDigitalIdentities/tsl:ServiceDigitalIdentity/tsl:DigitalId/tsl:X509Certificate',
      pointer,
    ) as Node[];

    const allowedSignerFingerprints = new Set<string>();
    for (const certNode of certNodes) {
      const fp = fingerprintFromB64(certNode.textContent || '');
      if (fp) allowedSignerFingerprints.add(fp);
    }

    if (allowedSignerFingerprints.size === 0) continue;

    result.push({
      country,
      tslLocation,
      allowedSignerFingerprints,
    });
  }

  return result;
}

/**
 * Extract every CA/QC service from a validated country TL DOM. Status
 * filtering and additional-service-info filtering are left to the caller —
 * we surface the raw entries so the caller can decide which to accept.
 */
export function parseTrustedListCaServices(
  doc: Document,
  country: string,
): CaServiceEntry[] {
  const services = select(
    '//tsl:TrustServiceProviderList/tsl:TrustServiceProvider/tsl:TSPServices/tsl:TSPService',
    doc,
  ) as Node[];

  const out: CaServiceEntry[] = [];

  for (const svc of services) {
    const typeId = textOf(
      select('./tsl:ServiceInformation/tsl:ServiceTypeIdentifier', svc),
    );
    if (typeId !== SVC_TYPE_CA_QC) continue;

    const statusUri = textOf(
      select('./tsl:ServiceInformation/tsl:ServiceStatus', svc),
    );

    const additionalServiceUris = (
      select(
        './tsl:ServiceInformation/tsl:ServiceInformationExtensions/tsl:Extension' +
          '/tsl:AdditionalServiceInformation/tsl:URI',
        svc,
      ) as Node[]
    )
      .map((n) => (n.textContent || '').trim())
      .filter((s) => s.length > 0);

    const caCertNodes = select(
      './tsl:ServiceInformation/tsl:ServiceDigitalIdentity/tsl:DigitalId/tsl:X509Certificate',
      svc,
    ) as Node[];

    const caCertsDer: Uint8Array[] = [];
    for (const node of caCertNodes) {
      const der = derFromB64(node.textContent || '');
      if (der) caCertsDer.push(der);
    }
    if (caCertsDer.length === 0) continue;

    out.push({
      country,
      serviceStatus: shortenStatus(statusUri),
      additionalServiceUris,
      caCertsDer,
    });
  }

  return out;
}

function textOf(nodes: unknown): string {
  if (!Array.isArray(nodes) || nodes.length === 0) return '';
  return ((nodes[0] as Node).textContent || '').trim();
}

function derFromB64(b64Text: string): Uint8Array | null {
  const cleaned = (b64Text || '').replace(/\s+/g, '');
  if (!cleaned) return null;
  try {
    return Uint8Array.from(Buffer.from(cleaned, 'base64'));
  } catch {
    return null;
  }
}

function fingerprintFromB64(b64Text: string): string | null {
  const der = derFromB64(b64Text);
  if (!der) return null;
  return createHash('sha256').update(der).digest('hex');
}

function shortenStatus(uri: string): ServiceStatus {
  if (!uri) return 'unknown';
  const tail = uri.split('/').pop()?.toLowerCase() ?? '';
  switch (tail) {
    case 'granted':
    case 'withdrawn':
    case 'revoked':
    case 'suspended':
    case 'undersupervision':
    case 'supervisionincessation':
    case 'supervisionceased':
    case 'supervisionrevoked':
    case 'accredited':
    case 'accreditationceased':
    case 'accreditationrevoked':
      return tail as ServiceStatus;
    default:
      return 'unknown';
  }
}

export { SVC_STATUS_GRANTED };
