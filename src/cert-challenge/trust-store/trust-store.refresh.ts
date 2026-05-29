import { Injectable, Logger, OnApplicationBootstrap } from '@nestjs/common';
import { Cron, CronExpression } from '@nestjs/schedule';
import { TrustStoreService } from './trust-store.service';
import { EidasPipelineService } from './eidas/eidas-pipeline.service';

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
  ) {}

  onApplicationBootstrap(): void {
    // Refresh runs in the background so we don't block app boot. The trust
    // store starts in `pending` state, so submitCert is fail-closed until
    // this completes.
    void this.refresh().catch((e) => {
      this.logger.error(
        `Initial trust store refresh failed: ${describe(e)}`,
      );
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
        const anchors = await this.pipeline.collectAnchors();
        this.trustStore.replaceAnchors(anchors);
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
