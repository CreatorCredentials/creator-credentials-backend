import { HttpService } from '@nestjs/axios';
import { Injectable, Logger } from '@nestjs/common';
import { X509Certificate } from '@peculiar/x509';
import { createHash } from 'crypto';
import { firstValueFrom } from 'rxjs';
import { XadesVerifier } from './xades-verifier';
import { parseTrustedListCaServices } from './tsl-parser';
import {
  ADD_INFO_FOR_ESEALS,
  ADD_INFO_FOR_ESIGNATURES,
  ADD_INFO_FOR_WEB_AUTH,
  CountryTslPointer,
} from './tsl-types';
import type { TrustAnchor, TrustedServiceType } from '../types';

/** Fetches a country TL, validates it, and turns it into trust anchors. */
@Injectable()
export class TlLoaderService {
  private readonly logger = new Logger(TlLoaderService.name);

  constructor(
    private readonly http: HttpService,
    private readonly xades: XadesVerifier,
  ) {}

  async load(pointer: CountryTslPointer): Promise<TrustAnchor[]> {
    let xml: string;
    try {
      xml = await this.fetchXml(pointer.tslLocation);
    } catch (e) {
      this.logger.warn(
        `[${pointer.country}] TL fetch failed: ${describe(e)}`,
      );
      return [];
    }

    let document: Document;
    try {
      ({ document } = await this.xades.verify(xml, {
        allowedSignerFingerprints: pointer.allowedSignerFingerprints,
      }));
    } catch (e) {
      this.logger.warn(
        `[${pointer.country}] TL XAdES validation failed: ${describe(e)}`,
      );
      return [];
    }

    const services = parseTrustedListCaServices(document, pointer.country);
    const anchors: TrustAnchor[] = [];

    for (const service of services) {
      if (service.serviceStatus !== 'granted') continue;

      const serviceTypes = decodeServiceTypes(service.additionalServiceUris);
      if (serviceTypes.length === 0) continue;

      for (const der of service.caCertsDer) {
        let cert: X509Certificate;
        try {
          cert = new X509Certificate(der);
        } catch {
          continue;
        }

        const fingerprint = createHash('sha256').update(der).digest('hex');
        anchors.push({
          fingerprint,
          subject: cert.subject,
          issuer: cert.issuer,
          country: pointer.country,
          serviceTypes,
          certificate: cert,
          der,
        });
      }
    }

    this.logger.log(
      `[${pointer.country}] TL accepted: ${anchors.length} QSeal/QSig anchors`,
    );
    return anchors;
  }

  private async fetchXml(url: string): Promise<string> {
    const response = await firstValueFrom(
      this.http.get<string>(url, {
        responseType: 'text',
        timeout: 30000,
        transformResponse: (data) =>
          typeof data === 'string' ? data : Buffer.from(data).toString('utf8'),
      }),
    );
    return response.data;
  }
}

/**
 * Map ETSI AdditionalServiceInformation URIs to our `TrustedServiceType` set.
 *
 * Per ETSI TS 119 612 §5.5.9, when a CA/QC service has no
 * AdditionalServiceInformation it is treated as issuing QC for any of the
 * three eIDAS purposes (eSig, eSeal, web auth). We intentionally accept that
 * and tag such CAs with both QSig + QSeal so the validator finds them when a
 * user submits a QSig OR QSeal cert chained to them.
 */
function decodeServiceTypes(uris: string[]): TrustedServiceType[] {
  if (uris.length === 0) {
    return ['QSeal', 'QSig'];
  }

  const types = new Set<TrustedServiceType>();
  let sawWebAuthOnly = uris.length > 0;
  for (const uri of uris) {
    if (uri === ADD_INFO_FOR_ESIGNATURES) {
      types.add('QSig');
      sawWebAuthOnly = false;
    } else if (uri === ADD_INFO_FOR_ESEALS) {
      types.add('QSeal');
      sawWebAuthOnly = false;
    } else if (uri === ADD_INFO_FOR_WEB_AUTH) {
      // QWAC-only CAs are intentionally excluded per the chosen scope.
    } else {
      // Unknown extension URI; ignore but don't auto-trust.
      sawWebAuthOnly = false;
    }
  }

  if (sawWebAuthOnly) return [];
  return Array.from(types);
}

function describe(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}
