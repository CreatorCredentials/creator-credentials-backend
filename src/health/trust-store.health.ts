import { Injectable } from '@nestjs/common';
import { HealthIndicator, HealthIndicatorResult } from '@nestjs/terminus';
import { TrustStoreService } from 'src/cert-challenge/trust-store/trust-store.service';

/**
 * `up` while the eIDAS trust store holds anchors, `down` while it is still
 * empty. A failed refresh after a successful load stays `up` (the previous
 * anchors remain in service) and is reported through `refresh`/`lastError`.
 */
@Injectable()
export class TrustStoreHealthIndicator extends HealthIndicator {
  constructor(private readonly trustStore: TrustStoreService) {
    super();
  }

  check(key: string): HealthIndicatorResult {
    const { status: refresh, ...details } = this.trustStore.summary();
    return this.getStatus(key, this.trustStore.isReady(), {
      refresh,
      ...details,
    });
  }
}
