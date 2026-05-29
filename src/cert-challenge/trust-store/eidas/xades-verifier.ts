import { Injectable } from '@nestjs/common';
import { Crypto } from '@peculiar/webcrypto';
import { DOMParser, XMLSerializer } from '@xmldom/xmldom';
import { X509Certificate, cryptoProvider } from '@peculiar/x509';
import * as xpath from 'xpath';
import * as xadesjs from 'xadesjs';
import { createHash } from 'crypto';

const DS_NS = 'http://www.w3.org/2000/09/xmldsig#';

let webCryptoEngineInstalled = false;

/**
 * xadesjs requires a WebCrypto implementation and DOM globals to run under
 * Node. We install the @peculiar/webcrypto polyfill and the xmldom DOM
 * implementation lazily on first use to avoid touching globals at import time
 * in test environments.
 */
function ensureEngine(): void {
  if (webCryptoEngineInstalled) return;

  const cryptoImpl = new Crypto();
  xadesjs.Application.setEngine('NodeJS', cryptoImpl);
  // @peculiar/x509 uses its own crypto provider for verify(); without this,
  // signature verification fails silently for some algorithms in Node.
  cryptoProvider.set(cryptoImpl);

  const g = globalThis as Record<string, unknown>;
  if (!g.DOMParser) g.DOMParser = DOMParser;
  if (!g.XMLSerializer) g.XMLSerializer = XMLSerializer;

  webCryptoEngineInstalled = true;
}

export interface XadesVerifyOptions {
  /**
   * SHA-256 fingerprints (lower-case hex) of the certificates that are
   * authorized to have signed this XML. The signing cert embedded in the
   * XAdES KeyInfo MUST match one of these or verification fails. This is the
   * mechanism that prevents an attacker from substituting a self-signed
   * payload with their own KeyInfo.
   */
  allowedSignerFingerprints: ReadonlySet<string>;
}

export interface XadesVerifyResult {
  /** The DOM document produced from `xml`, suitable for downstream parsing. */
  document: Document;
  /** The signing certificate that was actually used to sign the document. */
  signingCertificate: X509Certificate;
}

@Injectable()
export class XadesVerifier {
  /**
   * Validates the XAdES-BES signature on `xml` against an allowed-signer set.
   *
   * Steps:
   *  1. Parse the XML.
   *  2. Locate the `<ds:Signature>` element.
   *  3. Run xadesjs verification (canonicalization + reference digests +
   *     signature value verification using the cert in KeyInfo).
   *  4. Extract the signing cert from KeyInfo and compare its SHA-256
   *     fingerprint against the allowed set.
   *
   * The allowed-signer check is what binds this signature to a known trust
   * anchor (e.g. the EU LOTL signer set, or a country-specific TL signer).
   * Without it, anyone could sign a forged TL with their own keypair and
   * embed the matching cert in KeyInfo — xadesjs would happily verify.
   */
  async verify(
    xml: string,
    options: XadesVerifyOptions,
  ): Promise<XadesVerifyResult> {
    ensureEngine();

    const doc = new DOMParser().parseFromString(xml, 'application/xml');

    const signatureNodes = doc.getElementsByTagNameNS(DS_NS, 'Signature');
    if (signatureNodes.length === 0) {
      throw new Error('XAdES verification failed: no <ds:Signature> element');
    }
    if (signatureNodes.length > 1) {
      throw new Error(
        `XAdES verification failed: expected a single signature, found ${signatureNodes.length}`,
      );
    }
    const signatureNode = signatureNodes.item(0)!;

    const signedXml = new xadesjs.SignedXml(doc as unknown as Document);
    try {
      signedXml.LoadXml(signatureNode);
    } catch (e) {
      throw new Error(
        `XAdES verification failed: malformed Signature element: ${describe(e)}`,
      );
    }

    let signatureValid: boolean;
    try {
      signatureValid = await signedXml.Verify();
    } catch (e) {
      throw new Error(
        `XAdES verification failed: ${describe(e)}`,
      );
    }
    if (!signatureValid) {
      throw new Error(
        'XAdES verification failed: signature does not match digests or signing key',
      );
    }

    const signingCertificate = this.extractSigningCertificate(signatureNode);
    const fingerprint = sha256Hex(signingCertificate.rawData);

    if (!options.allowedSignerFingerprints.has(fingerprint)) {
      throw new Error(
        `XAdES verification failed: signing certificate ${fingerprint} is not in the allowed signer set`,
      );
    }

    return {
      document: doc as unknown as Document,
      signingCertificate,
    };
  }

  private extractSigningCertificate(signatureNode: Node): X509Certificate {
    const select = xpath.useNamespaces({ ds: DS_NS });
    const certNodes = select(
      './/ds:KeyInfo/ds:X509Data/ds:X509Certificate',
      signatureNode,
    ) as Node[];

    if (!certNodes || certNodes.length === 0) {
      throw new Error(
        'XAdES verification failed: signing cert missing from <ds:KeyInfo>',
      );
    }

    // When multiple X509Certificate elements are present, the EU TSL convention
    // is that the first is the signing cert and any others are intermediates.
    const base64 = (certNodes[0].textContent || '').replace(/\s+/g, '');
    if (!base64) {
      throw new Error(
        'XAdES verification failed: empty <ds:X509Certificate> element',
      );
    }

    let der: Uint8Array;
    try {
      der = Uint8Array.from(Buffer.from(base64, 'base64'));
    } catch (e) {
      throw new Error(
        `XAdES verification failed: signing cert is not valid base64: ${describe(e)}`,
      );
    }

    try {
      return new X509Certificate(der);
    } catch (e) {
      throw new Error(
        `XAdES verification failed: signing cert could not be parsed as X.509: ${describe(e)}`,
      );
    }
  }
}

function sha256Hex(data: ArrayBuffer | Uint8Array): string {
  const buf = data instanceof Uint8Array ? data : new Uint8Array(data);
  return createHash('sha256').update(buf).digest('hex').toLowerCase();
}

function describe(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}
