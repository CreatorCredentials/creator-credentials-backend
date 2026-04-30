import { HttpService } from '@nestjs/axios';
import { Injectable, Logger } from '@nestjs/common';
import { firstValueFrom } from 'rxjs';
import { XadesVerifier } from './xades-verifier';
import { LotlPivotBootstrap } from './pivot-bootstrap';
import { parseLotlCountryPointers } from './tsl-parser';
import type { CountryTslPointer } from './tsl-types';

const LOTL_URL = 'https://ec.europa.eu/tools/lotl/eu-lotl.xml';

/** Fetches and parses the EU LOTL into a list of country TL pointers. */
@Injectable()
export class LotlLoaderService {
  private readonly logger = new Logger(LotlLoaderService.name);

  constructor(
    private readonly http: HttpService,
    private readonly xades: XadesVerifier,
    private readonly bootstrap: LotlPivotBootstrap,
  ) {}

  async load(): Promise<CountryTslPointer[]> {
    const url = process.env.EIDAS_LOTL_URL || LOTL_URL;
    this.logger.log(`Fetching EU LOTL from ${url}`);
    const xml = await this.fetchXml(url);

    const allowedSignerFingerprints =
      await this.bootstrap.loadAllowedSignerFingerprints();

    const { document, signingCertificate } = await this.xades.verify(xml, {
      allowedSignerFingerprints,
    });
    this.logger.log(
      `LOTL XAdES signature verified by ${signingCertificate.subject}`,
    );

    const pointers = parseLotlCountryPointers(document);
    this.logger.log(`LOTL contains ${pointers.length} country TL pointers`);
    return pointers;
  }

  private async fetchXml(url: string): Promise<string> {
    const response = await firstValueFrom(
      this.http.get<string>(url, {
        responseType: 'text',
        timeout: 30000,
        // The TSL service occasionally serves XML as `text/xml` or
        // `application/octet-stream`; we always want the raw bytes as text.
        transformResponse: (data) =>
          typeof data === 'string' ? data : Buffer.from(data).toString('utf8'),
      }),
    );
    return response.data;
  }
}
