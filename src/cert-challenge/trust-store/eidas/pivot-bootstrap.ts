import { Injectable, Logger } from '@nestjs/common';
import type { X509Certificate } from '@peculiar/x509';
import * as path from 'path';
import { readPemCertificatesFromDir, sha256Fingerprint } from './pem';

/**
 * Loads the bootstrap trust anchors that are authorised to XAdES-sign the EU
 * LOTL. These are PEM files placed under `certificates/eidas/lotl-signers/`.
 *
 * This is the only out-of-band trust anchor in the eIDAS pipeline; everything
 * else (per-country TL signers, QSeal/QSig CA anchors) is derived from a
 * LOTL document whose signature has been verified against this set.
 */
@Injectable()
export class LotlPivotBootstrap {
  private readonly logger = new Logger(LotlPivotBootstrap.name);
  private readonly defaultDir = path.resolve(
    process.cwd(),
    'certificates',
    'eidas',
    'lotl-signers',
  );

  async loadAllowedSignerFingerprints(): Promise<Set<string>> {
    const dir = process.env.EIDAS_LOTL_SIGNERS_DIR || this.defaultDir;
    let certs: X509Certificate[];
    try {
      certs = await readPemCertificatesFromDir(dir);
    } catch (e) {
      throw new Error(
        `LOTL bootstrap directory ${dir} cannot be read: ${describe(e)}`,
      );
    }

    const fingerprints = new Set<string>();
    for (const cert of certs) {
      const fp = sha256Fingerprint(cert);
      fingerprints.add(fp);
      this.logger.log(
        `LOTL signer anchor loaded: ${cert.subject} (sha256=${fp.slice(
          0,
          16,
        )}…)`,
      );
    }

    if (fingerprints.size === 0) {
      throw new Error(
        `No LOTL signer anchors found under ${dir}. Cannot validate the EU LOTL ` +
          `XAdES signature without an out-of-band trust anchor.`,
      );
    }

    return fingerprints;
  }
}

function describe(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}
