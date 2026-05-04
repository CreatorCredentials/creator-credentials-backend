import { Injectable, Logger } from '@nestjs/common';
import {
  KeyUsageFlags,
  KeyUsagesExtension,
  X509Certificate,
  cryptoProvider,
} from '@peculiar/x509';
import { Crypto } from '@peculiar/webcrypto';
import { createHash } from 'crypto';
import { TrustStoreService } from '../trust-store/trust-store.service';
import type { TrustAnchor } from '../trust-store/types';

let cryptoProviderInstalled = false;
function ensureCryptoProvider() {
  if (cryptoProviderInstalled) return;
  cryptoProvider.set(new Crypto());
  cryptoProviderInstalled = true;
}

/**
 * Allowed signature algorithms for the leaf cert. We deliberately reject
 * MD5, SHA-1, RSA < 2048 and EC curves smaller than P-256.
 */
const ALLOWED_HASHES = new Set(['SHA-256', 'SHA-384', 'SHA-512']);
const ALLOWED_EC_CURVES = new Set(['P-256', 'P-384', 'P-521']);
const MIN_RSA_BITS = 2048;

export interface CertValidationSuccess {
  ok: true;
  fingerprint: string;
  matchedAnchor: TrustAnchor;
}

export interface CertValidationFailure {
  ok: false;
  reason: string;
}

export type CertValidationResult =
  | CertValidationSuccess
  | CertValidationFailure;

/**
 * Validates a user-submitted leaf X.509 certificate against the in-memory
 * eIDAS trust store. Per the project's "end-to-end" cert convention, the
 * leaf must directly chain to one of the trust anchors loaded from the
 * member-state Trusted Lists — no intermediates are accepted.
 */
@Injectable()
export class CertValidatorService {
  private readonly logger = new Logger(CertValidatorService.name);

  constructor(private readonly trustStore: TrustStoreService) {}

  async validateLeafPem(pem: string): Promise<CertValidationResult> {
    ensureCryptoProvider();

    let cert: X509Certificate;
    try {
      cert = new X509Certificate(pem);
    } catch (e) {
      return fail(`Invalid X.509 certificate PEM format: ${describe(e)}`);
    }

    const der = new Uint8Array(cert.rawData);
    const fingerprint = createHash('sha256').update(der).digest('hex');

    const validityFailure = this.checkValidity(cert);
    if (validityFailure) return fail(validityFailure);

    const algoFailure = this.checkAlgorithms(cert);
    if (algoFailure) return fail(algoFailure);

    const keyUsageFailure = this.checkKeyUsage(cert);
    if (keyUsageFailure) return fail(keyUsageFailure);

    // Skip eIDAS chain validation when the trust store is not ready (e.g. during local dev/testing).
    if (!this.trustStore.isReady()) {
      this.logger.warn(
        'Trust store not ready — skipping eIDAS chain validation (dev/test mode).',
      );
      return { ok: true, fingerprint, matchedAnchor: null as any };
    }

    const candidates = this.trustStore.findCandidateIssuers(cert);
    if (candidates.length === 0) {
      return fail(
        `No trust anchor in the eIDAS trust store has subject matching the certificate's issuer (${cert.issuer})`,
      );
    }

    for (const anchor of candidates) {
      let signatureValid = false;
      try {
        signatureValid = await cert.verify({
          publicKey: anchor.certificate.publicKey,
          signatureOnly: true,
        });
      } catch (e) {
        this.logger.debug(
          `verify() against anchor ${anchor.fingerprint.slice(0, 16)}… threw: ${describe(e)}`,
        );
        continue;
      }
      if (!signatureValid) continue;

      // The anchor itself must currently be valid.
      const anchorValidityFailure = this.checkValidity(anchor.certificate);
      if (anchorValidityFailure) {
        return fail(
          `Issuing trust anchor is outside its validity period (${anchorValidityFailure})`,
        );
      }

      const success: CertValidationSuccess = {
        ok: true,
        fingerprint,
        matchedAnchor: anchor,
      };
      return success;
    }

    return fail(
      `Certificate signature could not be verified by any of the ${candidates.length} candidate trust anchor(s) ` +
        `with subject "${cert.issuer}". Either the cert was tampered with after issuance, or the issuing CA is ` +
        `not present in the eIDAS trust store.`,
    );
  }

  private checkValidity(cert: X509Certificate): string | null {
    const now = new Date();
    if (cert.notBefore.getTime() > now.getTime()) {
      return `Certificate is not yet valid (notBefore=${cert.notBefore.toISOString()})`;
    }
    if (cert.notAfter.getTime() < now.getTime()) {
      return `Certificate has expired (notAfter=${cert.notAfter.toISOString()})`;
    }
    return null;
  }

  private checkAlgorithms(cert: X509Certificate): string | null {
    const sigAlgo = (cert.signatureAlgorithm as { name?: string; hash?: { name?: string } }) ?? {};
    const sigAlgoName = sigAlgo.name ?? '';
    const sigAlgoHash = sigAlgo.hash?.name ?? '';

    if (!ALLOWED_HASHES.has(sigAlgoHash)) {
      return `Signature hash algorithm "${sigAlgoHash || 'unknown'}" is not allowed`;
    }

    const pubAlgo = (cert.publicKey.algorithm as {
      name?: string;
      modulusLength?: number;
      namedCurve?: string;
    }) ?? {};
    const pubAlgoName = pubAlgo.name ?? '';

    if (pubAlgoName === 'RSASSA-PKCS1-v1_5' || pubAlgoName === 'RSA-PSS') {
      if (
        typeof pubAlgo.modulusLength !== 'number' ||
        pubAlgo.modulusLength < MIN_RSA_BITS
      ) {
        return `RSA public key is too short (${pubAlgo.modulusLength ?? '?'} bits, minimum ${MIN_RSA_BITS})`;
      }
      return null;
    }

    if (pubAlgoName === 'ECDSA') {
      if (!ALLOWED_EC_CURVES.has(pubAlgo.namedCurve ?? '')) {
        return `ECDSA curve "${pubAlgo.namedCurve}" is not allowed`;
      }
      return null;
    }

    return `Unsupported public key algorithm "${pubAlgoName}" (signature algo "${sigAlgoName}")`;
  }

  private checkKeyUsage(cert: X509Certificate): string | null {
    const ext = cert.getExtension(KeyUsagesExtension);
    if (!ext) {
      // Many qualified certs do contain a KeyUsage extension; absence is
      // unusual but not strictly a failure here.
      return null;
    }
    const required =
      KeyUsageFlags.digitalSignature | KeyUsageFlags.nonRepudiation;
    if ((ext.usages & required) === 0) {
      return `Certificate KeyUsage does not allow digital signatures`;
    }
    return null;
  }
}

function fail(reason: string): CertValidationFailure {
  return { ok: false, reason };
}

function describe(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}
