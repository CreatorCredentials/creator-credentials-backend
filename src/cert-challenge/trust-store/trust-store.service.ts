import { Injectable, Logger, ServiceUnavailableException } from '@nestjs/common';
import { X509Certificate } from '@peculiar/x509';
import type { TrustAnchor, TrustStoreState } from './types';

/**
 * In-memory store of eIDAS trust anchors.
 *
 * Anchors are keyed by their SHA-256 fingerprint and indexed by issuer DN to
 * allow O(1) "candidate issuers" lookups when validating a leaf certificate.
 *
 * The store starts in `pending` state and only becomes `ready` after a
 * successful refresh from the EU LOTL pipeline. While not `ready`, the
 * `requireReady()` gate throws 503 (fail-closed).
 */
@Injectable()
export class TrustStoreService {
  private readonly logger = new Logger(TrustStoreService.name);

  private byFingerprint = new Map<string, TrustAnchor>();
  private bySubject = new Map<string, TrustAnchor[]>();
  private state: TrustStoreState = { status: 'pending' };

  getState(): TrustStoreState {
    return this.state;
  }

  isReady(): boolean {
    return this.state.status === 'ready';
  }

  requireReady(): void {
    if (this.state.status !== 'ready') {
      throw new ServiceUnavailableException(
        'Certificate trust store is not ready yet. Please retry shortly.',
      );
    }
  }

  /** Look up trust anchors that could potentially be the issuer of `leaf`. */
  findCandidateIssuers(leaf: X509Certificate): TrustAnchor[] {
    return this.bySubject.get(this.normalizeDn(leaf.issuer)) ?? [];
  }

  getAllAnchors(): TrustAnchor[] {
    return Array.from(this.byFingerprint.values());
  }

  /**
   * Atomically replace the store contents. Called by the refresh pipeline
   * once a full LOTL + per-country TL load has completed.
   */
  replaceAnchors(anchors: TrustAnchor[]): void {
    const byFingerprint = new Map<string, TrustAnchor>();
    const bySubject = new Map<string, TrustAnchor[]>();

    for (const anchor of anchors) {
      const existing = byFingerprint.get(anchor.fingerprint);
      if (existing) {
        // The same CA cert can appear in multiple member states' TLs; merge
        // the service-type set rather than dropping duplicates.
        const merged: TrustAnchor = {
          ...existing,
          serviceTypes: Array.from(
            new Set([...existing.serviceTypes, ...anchor.serviceTypes]),
          ) as TrustAnchor['serviceTypes'],
        };
        byFingerprint.set(anchor.fingerprint, merged);
        continue;
      }
      byFingerprint.set(anchor.fingerprint, anchor);

      const subjectKey = this.normalizeDn(anchor.subject);
      const list = bySubject.get(subjectKey) ?? [];
      list.push(anchor);
      bySubject.set(subjectKey, list);
    }

    this.byFingerprint = byFingerprint;
    this.bySubject = bySubject;
    this.state = {
      status: 'ready',
      loadedAt: new Date(),
      anchorCount: byFingerprint.size,
    };

    this.logger.log(
      `Trust store ready: ${byFingerprint.size} anchors from eIDAS LOTL.`,
    );
  }

  markError(error: unknown): void {
    const message = error instanceof Error ? error.message : String(error);
    const previousLoadedAt =
      this.state.status === 'ready' ? this.state.loadedAt : null;
    this.state = {
      status: 'error',
      loadedAt: previousLoadedAt,
      error: message,
    };
    this.logger.error(`Trust store refresh failed: ${message}`);
  }

  /**
   * Normalize a Distinguished Name for matching. `@peculiar/x509` already
   * returns RFC 4514 strings, but whitespace/case around RDN separators can
   * differ between implementations, so we normalize defensively.
   */
  private normalizeDn(dn: string): string {
    return dn
      .split(',')
      .map((p) => p.trim())
      .join(',')
      .toLowerCase();
  }
}
