import { TrustStoreRefreshService } from './trust-store.refresh';
import { TrustStoreService } from './trust-store.service';
import { EidasPipelineService } from './eidas/eidas-pipeline.service';
import { ExtraAnchorsLoader } from './eidas/extra-anchors.loader';
import type { TrustAnchor } from './types';

function anchor(subject: string, country = 'EU'): TrustAnchor {
  return {
    fingerprint: subject,
    subject,
    issuer: subject,
    country,
    serviceTypes: ['QSeal'],
    certificate: { subject } as TrustAnchor['certificate'],
    der: new Uint8Array(),
  };
}

describe('TrustStoreRefreshService', () => {
  const pipeline = { collectAnchors: jest.fn() };
  const extraAnchors = { load: jest.fn() };
  let trustStore: TrustStoreService;
  let refresh: TrustStoreRefreshService;

  beforeEach(() => {
    jest.resetAllMocks();
    trustStore = new TrustStoreService();
    refresh = new TrustStoreRefreshService(
      trustStore,
      pipeline as unknown as EidasPipelineService,
      extraAnchors as unknown as ExtraAnchorsLoader,
    );
  });

  it('publishes LOTL anchors together with the extra anchors', async () => {
    pipeline.collectAnchors.mockResolvedValue([anchor('CN=EU CA')]);
    extraAnchors.load.mockResolvedValue([anchor('CN=Dev CA', 'LOCAL')]);

    await refresh.refresh();

    expect(trustStore.getAllAnchors().map((a) => a.subject)).toEqual([
      'CN=EU CA',
      'CN=Dev CA',
    ]);
  });

  it('records the failure and keeps the store closed when the pipeline fails', async () => {
    pipeline.collectAnchors.mockRejectedValue(new Error('LOTL down'));
    extraAnchors.load.mockResolvedValue([]);

    await expect(refresh.refresh()).rejects.toThrow('LOTL down');

    expect(trustStore.isReady()).toBe(false);
    expect(trustStore.summary().lastError).toBe('LOTL down');
  });

  it('shares one in-flight refresh between concurrent callers', async () => {
    pipeline.collectAnchors.mockResolvedValue([anchor('CN=EU CA')]);
    extraAnchors.load.mockResolvedValue([]);

    await Promise.all([refresh.refresh(), refresh.refresh()]);

    expect(pipeline.collectAnchors).toHaveBeenCalledTimes(1);
  });
});
