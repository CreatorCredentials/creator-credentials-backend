import { Injectable, Logger, OnApplicationBootstrap } from '@nestjs/common';
import { Cron, CronExpression } from '@nestjs/schedule';
import { TrustStoreService } from './trust-store.service';
import { EidasPipelineService } from './eidas/eidas-pipeline.service';
import { ExtraAnchorsLoader } from './eidas/extra-anchors.loader';

/**
 * Drives the trust store lifecycle: an initial refresh on application start,
 * then a daily refresh via cron. Refresh failures keep the previously loaded
 * anchor set in place; only a successful refresh replaces it.
 */
@Injectable()
export class TrustStoreRefreshService implements OnApplicationBootstrap {
  private readonly logger = new Logger(TrustStoreRefreshService.name);
  private inFlight: Promise<void> | null = null;

  constructor(
    private readonly trustStore: TrustStoreService,
    private readonly pipeline: EidasPipelineService,
    private readonly extraAnchors: ExtraAnchorsLoader,
  ) {}

  onApplicationBootstrap(): void {
    // Refresh runs in the background so we don't block app boot. The trust
    // store starts empty, so submitCert answers 503 until this completes
    // (unless EIDAS_CHAIN_VALIDATION=skip).
    void this.refresh().catch((e) => {
      this.logger.error(`Initial trust store refresh failed: ${describe(e)}`);
    });
  }

  @Cron(CronExpression.EVERY_DAY_AT_3AM)
  async scheduledRefresh(): Promise<void> {
    try {
      await this.refresh();
    } catch (e) {
      this.logger.error(`Scheduled trust store refresh failed: ${describe(e)}`);
    }
  }

  /** Manually trigger a refresh; safe to call concurrently. */
  async refresh(): Promise<void> {
    if (this.inFlight) {
      this.logger.log('Trust store refresh already in flight; awaiting it');
      return this.inFlight;
    }

    this.inFlight = (async () => {
      try {
        const [anchors, extra] = await Promise.all([
          this.pipeline.collectAnchors(),
          this.extraAnchors.load(),
        ]);
        this.trustStore.replaceAnchors([...anchors, ...extra]);
      } catch (e) {
        this.trustStore.markError(e);
        throw e;
      }
    })().finally(() => {
      this.inFlight = null;
    });

    return this.inFlight;
  }
}

function describe(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}
