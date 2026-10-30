import { ServiceUnavailableException } from '@nestjs/common';
import { TrustStoreService } from './trust-store.service';
import type { TrustAnchor } from './types';

function anchor(subject: string, fingerprint = subject): TrustAnchor {
  return {
    fingerprint,
    subject,
    issuer: subject,
    country: 'EU',
    serviceTypes: ['QSeal'],
    certificate: { subject } as TrustAnchor['certificate'],
    der: new Uint8Array(),
  };
}

describe('TrustStoreService', () => {
  let store: TrustStoreService;

  beforeEach(() => {
    store = new TrustStoreService();
  });

  it('starts empty and fails closed', () => {
    expect(store.isReady()).toBe(false);
    expect(() => store.requireReady()).toThrow(ServiceUnavailableException);
    expect(store.summary()).toEqual({
      status: 'pending',
      anchors: 0,
      lastRefresh: null,
      lastError: null,
    });
  });

  it('is ready once anchors are loaded', () => {
    store.replaceAnchors([anchor('CN=A'), anchor('CN=B')]);

    expect(store.isReady()).toBe(true);
    expect(() => store.requireReady()).not.toThrow();
    expect(store.summary()).toMatchObject({ status: 'ready', anchors: 2 });
    expect(store.summary().lastRefresh).toEqual(expect.any(String));
  });

  it('keeps serving the previous anchors after a failed refresh', () => {
    store.replaceAnchors([anchor('CN=A')]);

    store.markError(new Error('LOTL unreachable'));

    expect(store.isReady()).toBe(true);
    expect(store.summary()).toMatchObject({
      status: 'error',
      anchors: 1,
      lastError: 'LOTL unreachable',
    });
    expect(store.summary().lastRefresh).toEqual(expect.any(String));
  });

  it('stays closed when the very first refresh fails', () => {
    store.markError('boom');

    expect(store.isReady()).toBe(false);
    expect(store.summary()).toEqual({
      status: 'error',
      anchors: 0,
      lastRefresh: null,
      lastError: 'boom',
    });
  });

  it('merges service types of a CA listed by several countries', () => {
    store.replaceAnchors([
      { ...anchor('CN=A', 'fp'), serviceTypes: ['QSeal'] },
      { ...anchor('CN=A', 'fp'), country: 'DE', serviceTypes: ['QSig'] },
    ]);

    expect(store.getAllAnchors()).toHaveLength(1);
    expect(store.getAllAnchors()[0].serviceTypes).toEqual(['QSeal', 'QSig']);
  });
});
