import { Injectable } from '@nestjs/common';
import {
  HealthCheckError,
  HealthIndicator,
  HealthIndicatorResult,
} from '@nestjs/terminus';
import { TrustStoreService } from 'src/cert-challenge/trust-store/trust-store.service';

/**
 * `up` while the eIDAS trust store holds anchors, `down` while it is still
 * empty (the first minute after boot, or a failed first refresh). Terminus only
 * counts an indicator as failed when it throws, so the empty store throws and
 * `/health` answers 503 until anchors are loaded. A failed refresh after a
 * successful load stays `up` (the previous anchors remain in service) and is
 * reported through `refresh`/`lastError`.
 */
@Injectable()
export class TrustStoreHealthIndicator extends HealthIndicator {
  constructor(private readonly trustStore: TrustStoreService) {
    super();
  }

  check(key: string): HealthIndicatorResult {
    const { status: refresh, ...details } = this.trustStore.summary();
    const result = this.getStatus(key, this.trustStore.isReady(), {
      refresh,
      ...details,
    });
    if (!this.trustStore.isReady()) {
      throw new HealthCheckError('eIDAS trust store is empty', result);
    }
    return result;
  }
}
