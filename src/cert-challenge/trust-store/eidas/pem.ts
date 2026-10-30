import { X509Certificate } from '@peculiar/x509';
import { createHash } from 'crypto';
import { promises as fs } from 'fs';
import * as path from 'path';

/** Parses every `CERTIFICATE` block in a PEM bundle; unparsable blocks are skipped. */
export function parsePemCertificates(pem: string): X509Certificate[] {
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
      // Skip unparsable blocks; the caller logs the problem at a higher level.
    }
  }
  return certs;
}

/** Reads every `*.pem` file in `dir` and returns all certificates found. */
export async function readPemCertificatesFromDir(
  dir: string,
): Promise<X509Certificate[]> {
  const entries = await fs.readdir(dir);
  const certs: X509Certificate[] = [];
  for (const entry of entries) {
    if (!entry.toLowerCase().endsWith('.pem')) continue;
    const content = await fs.readFile(path.join(dir, entry), 'utf8');
    certs.push(...parsePemCertificates(content));
  }
  return certs;
}

export function sha256Fingerprint(cert: X509Certificate): string {
  return createHash('sha256')
    .update(new Uint8Array(cert.rawData))
    .digest('hex');
}
