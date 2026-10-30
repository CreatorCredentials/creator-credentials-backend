import { HealthCheckError } from '@nestjs/terminus';
import { TrustStoreService } from 'src/cert-challenge/trust-store/trust-store.service';
import { TrustStoreHealthIndicator } from './trust-store.health';

describe('TrustStoreHealthIndicator', () => {
  const trustStore = { isReady: jest.fn(), summary: jest.fn() };
  const indicator = new TrustStoreHealthIndicator(
    trustStore as unknown as TrustStoreService,
  );

  it('fails the health check while the store is empty', () => {
    trustStore.isReady.mockReturnValue(false);
    trustStore.summary.mockReturnValue({ status: 'pending', anchors: 0 });

    expect(() => indicator.check('trustStore')).toThrow(HealthCheckError);
    try {
      indicator.check('trustStore');
    } catch (error) {
      expect((error as HealthCheckError).causes).toEqual({
        trustStore: { status: 'down', refresh: 'pending', anchors: 0 },
      });
    }
  });

  it('is up with the refresh details once anchors are loaded', () => {
    trustStore.isReady.mockReturnValue(true);
    trustStore.summary.mockReturnValue({
      status: 'error',
      anchors: 875,
      lastError: 'LOTL unreachable',
    });

    expect(indicator.check('trustStore')).toEqual({
      trustStore: {
        status: 'up',
        refresh: 'error',
        anchors: 875,
        lastError: 'LOTL unreachable',
      },
    });
  });
});
