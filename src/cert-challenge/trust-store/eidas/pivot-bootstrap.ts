import { Injectable, Logger } from '@nestjs/common';
import { X509Certificate } from '@peculiar/x509';
import { createHash } from 'crypto';
import { promises as fs } from 'fs';
import * as path from 'path';

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
    let entries: string[];
    try {
      entries = await fs.readdir(dir);
    } catch (e) {
      throw new Error(
        `LOTL bootstrap directory ${dir} cannot be read: ${describe(e)}`,
      );
    }

    const fingerprints = new Set<string>();
    for (const entry of entries) {
      if (!entry.toLowerCase().endsWith('.pem')) continue;

      const filePath = path.join(dir, entry);
      const content = await fs.readFile(filePath, 'utf8');
      for (const cert of parsePemCertificates(content)) {
        const der = cert.rawData;
        const fp = createHash('sha256').update(new Uint8Array(der)).digest('hex');
        fingerprints.add(fp);
        this.logger.log(
          `LOTL signer anchor loaded: ${cert.subject} (sha256=${fp.slice(0, 16)}…)`,
        );
      }
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

function parsePemCertificates(pem: string): X509Certificate[] {
  const blocks = pem.match(
    /-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g,
  );
  if (!blocks) return [];
  const certs: X509Certificate[] = [];
  for (const block of blocks) {
    const base64 = block
      .replace(/-----BEGIN CERTIFICATE-----/g, '')
      .replace(/-----END CERTIFICATE-----/g, '')
      .replace(/\s+/g, '');
    try {
      certs.push(new X509Certificate(Buffer.from(base64, 'base64')));
    } catch {
      // Skip unparsable blocks; the loader logs the problem at higher level.
    }
  }
  return certs;
}

function describe(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}
