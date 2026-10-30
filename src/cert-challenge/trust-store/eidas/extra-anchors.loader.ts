import { Injectable, Logger } from '@nestjs/common';
import type { X509Certificate } from '@peculiar/x509';
import type { TrustAnchor } from '../types';
import { readPemCertificatesFromDir, sha256Fingerprint } from './pem';

export const EXTRA_ANCHORS_DIR_ENV = 'EIDAS_EXTRA_ANCHORS_DIR';

/** Marker country for anchors that did not come from a member-state TL. */
export const EXTRA_ANCHOR_COUNTRY = 'LOCAL';

/**
 * Loads additional trust anchors from the PEM files in `EIDAS_EXTRA_ANCHORS_DIR`.
 *
 * This exists so a development environment can run the full cert-challenge
 * flow against a self-made CA. Anchors from here are not eIDAS-listed and the
 * loader says so loudly; the variable must stay unset on production.
 */
@Injectable()
export class ExtraAnchorsLoader {
  private readonly logger = new Logger(ExtraAnchorsLoader.name);

  async load(): Promise<TrustAnchor[]> {
    const dir = process.env[EXTRA_ANCHORS_DIR_ENV]?.trim();
    if (!dir) return [];

    let certs: X509Certificate[];
    try {
      certs = await readPemCertificatesFromDir(dir);
    } catch (e) {
      throw new Error(
        `${EXTRA_ANCHORS_DIR_ENV}=${dir} cannot be read: ${describe(e)}`,
      );
    }

    const anchors = certs.map(
      (certificate): TrustAnchor => ({
        fingerprint: sha256Fingerprint(certificate),
        subject: certificate.subject,
        issuer: certificate.issuer,
        country: EXTRA_ANCHOR_COUNTRY,
        serviceTypes: ['QSeal', 'QSig'],
        certificate,
        der: new Uint8Array(certificate.rawData),
      }),
    );

    for (const anchor of anchors) {
      this.logger.warn(
        `Extra trust anchor (NOT eIDAS-listed) loaded from ${dir}: ${anchor.subject}`,
      );
    }
    return anchors;
  }
}

function describe(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}
