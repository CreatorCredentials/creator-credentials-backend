/**
 * Maintenance script: fetch the live EU LOTL, extract its XAdES signing
 * cert(s) from KeyInfo, and write them as PEMs into
 * `certificates/eidas/lotl-signers/`.
 *
 * Run when the EU rotates the LOTL signer (announced via the OJ):
 *
 *     pnpm ts-node scripts/refresh-lotl-bootstrap.ts
 *
 * The script prints each cert's SHA-256 fingerprint, Subject DN, Issuer DN,
 * and validity window. Verify them against the OJEU before committing.
 */

import { promises as fs } from 'fs';
import * as path from 'path';
import { DOMParser } from '@xmldom/xmldom';
import * as xpath from 'xpath';
import { X509Certificate } from '@peculiar/x509';
import { createHash } from 'crypto';

const LOTL_URL = process.env.EIDAS_LOTL_URL || 'https://ec.europa.eu/tools/lotl/eu-lotl.xml';
const OUT_DIR = path.resolve(process.cwd(), 'certificates', 'eidas', 'lotl-signers');
const DS_NS = 'http://www.w3.org/2000/09/xmldsig#';

async function main() {
  console.log(`Fetching LOTL from ${LOTL_URL}`);
  const res = await fetch(LOTL_URL);
  if (!res.ok) {
    throw new Error(`LOTL fetch failed: HTTP ${res.status}`);
  }
  const xml = await res.text();

  const doc = new DOMParser().parseFromString(xml, 'application/xml');
  const select = xpath.useNamespaces({ ds: DS_NS });
  const nodes = select(
    '//ds:Signature/ds:KeyInfo/ds:X509Data/ds:X509Certificate',
    doc as unknown as Node,
  ) as Node[];

  if (!nodes.length) {
    throw new Error('LOTL has no <ds:Signature>/<ds:KeyInfo>/<ds:X509Certificate>');
  }

  await fs.mkdir(OUT_DIR, { recursive: true });

  for (const node of nodes) {
    const b64 = (node.textContent || '').replace(/\s+/g, '');
    const der = Buffer.from(b64, 'base64');
    const fp = createHash('sha256').update(der).digest('hex');
    const cert = new X509Certificate(der);

    const month = cert.notBefore.toISOString().slice(0, 7); // YYYY-MM
    const filename = `eu-lotl-signer-${month}.pem`;
    const filepath = path.join(OUT_DIR, filename);

    const wrapped = b64.match(/.{1,64}/g)!.join('\n');
    const pem = [
      `Subject: ${cert.subject}`,
      `Issuer:  ${cert.issuer}`,
      `NotBefore: ${cert.notBefore.toISOString()}`,
      `NotAfter:  ${cert.notAfter.toISOString()}`,
      `SHA-256:   ${fp}`,
      ``,
      `Refreshed by scripts/refresh-lotl-bootstrap.ts on ${new Date().toISOString()}.`,
      `Verify the SHA-256 against the EU Official Journal before committing.`,
      ``,
      `-----BEGIN CERTIFICATE-----`,
      wrapped,
      `-----END CERTIFICATE-----`,
      ``,
    ].join('\n');

    await fs.writeFile(filepath, pem, 'utf8');

    console.log('---');
    console.log(`Subject:  ${cert.subject}`);
    console.log(`Issuer :  ${cert.issuer}`);
    console.log(`Validity: ${cert.notBefore.toISOString()} → ${cert.notAfter.toISOString()}`);
    console.log(`SHA-256:  ${fp}`);
    console.log(`Wrote:    ${path.relative(process.cwd(), filepath)}`);
  }

  console.log('---');
  console.log('Done. Verify the SHA-256 fingerprints against the EU OJ before committing.');
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
