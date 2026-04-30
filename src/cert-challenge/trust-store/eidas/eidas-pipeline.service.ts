import { Injectable, Logger } from '@nestjs/common';
import { LotlLoaderService } from './lotl-loader.service';
import { TlLoaderService } from './tl-loader.service';
import type { TrustAnchor } from '../types';

/**
 * Orchestrates a full LOTL refresh: validate LOTL XAdES, walk every country
 * TL pointer, validate each TL XAdES against its announced signer set, and
 * collect QSeal/QSig CA anchors from all of them.
 *
 * Country-level failures are logged and skipped — one country's broken TL
 * must not invalidate anchors from the other 26.
 */
@Injectable()
export class EidasPipelineService {
  private readonly logger = new Logger(EidasPipelineService.name);

  constructor(
    private readonly lotl: LotlLoaderService,
    private readonly tl: TlLoaderService,
  ) {}

  async collectAnchors(): Promise<TrustAnchor[]> {
    const pointers = await this.lotl.load();

    const allAnchors: TrustAnchor[] = [];
    let okCountries = 0;
    let failCountries = 0;

    for (const pointer of pointers) {
      try {
        const anchors = await this.tl.load(pointer);
        if (anchors.length > 0) okCountries++;
        allAnchors.push(...anchors);
      } catch (e) {
        failCountries++;
        this.logger.warn(
          `[${pointer.country}] TL pipeline error: ${
            e instanceof Error ? e.message : String(e)
          }`,
        );
      }
    }

    this.logger.log(
      `eIDAS refresh complete: ${allAnchors.length} anchors from ${okCountries} countries (${failCountries} failed)`,
    );

    if (allAnchors.length === 0) {
      throw new Error(
        'eIDAS refresh produced zero trust anchors; refusing to publish an empty trust store',
      );
    }
    return allAnchors;
  }
}
