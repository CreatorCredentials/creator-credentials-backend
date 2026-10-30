import {
  Injectable,
  Logger,
  ServiceUnavailableException,
} from '@nestjs/common';
import { X509Certificate } from '@peculiar/x509';
import type { TrustAnchor, TrustStoreState, TrustStoreSummary } from './types';

/**
 * In-memory store of eIDAS trust anchors.
 *
 * Anchors are keyed by their SHA-256 fingerprint and indexed by issuer DN to
 * allow O(1) "candidate issuers" lookups when validating a leaf certificate.
 *
 * The store starts empty (`pending`) and is filled by the first successful
 * refresh from the EU LOTL pipeline. A later failed refresh is recorded as
 * `error` but keeps the anchors already loaded, so `isReady()` means "anchors
 * are available", not "the last refresh succeeded". `requireReady()` throws
 * 503 while the store is still empty (fail-closed).
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
    return this.byFingerprint.size > 0;
  }

  requireReady(): void {
    if (!this.isReady()) {
      throw new ServiceUnavailableException(
        'Certificate trust store is not ready yet. Please retry shortly.',
      );
    }
  }

  summary(): TrustStoreSummary {
    const { state } = this;
    return {
      status: state.status,
      anchors: this.byFingerprint.size,
      lastRefresh:
        state.status === 'pending' || !state.loadedAt
          ? null
          : state.loadedAt.toISOString(),
      lastError: state.status === 'error' ? state.error : null,
    };
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

    this.logger.log(`Trust store ready: ${byFingerprint.size} anchors.`);
  }

  /** Record a failed refresh; anchors from the previous refresh stay in service. */
  markError(error: unknown): void {
    const message = error instanceof Error ? error.message : String(error);
    const previousLoadedAt =
      this.state.status === 'pending' ? null : this.state.loadedAt;
    this.state = {
      status: 'error',
      loadedAt: previousLoadedAt,
      anchorCount: this.byFingerprint.size,
      error: message,
    };
    this.logger.error(
      `Trust store refresh failed, keeping ${this.byFingerprint.size} previously loaded anchors: ${message}`,
    );
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
