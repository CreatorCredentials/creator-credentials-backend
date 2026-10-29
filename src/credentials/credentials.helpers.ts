import * as fs from 'fs';
import * as crypto from 'crypto';
import { v4 as uuidv4 } from 'uuid';
import { CreateMemberCredentialDto } from './dto/create-member-credential.dto';
import { User } from 'src/users/user.entity';
import * as jwt from 'jsonwebtoken';
import { CreateEmailCredentialDto } from './dto/create-email-credential.dto';
import { CreateConnectCredentialDto } from './dto/create-connect-credential.dto';
import { CreateDomainCredentialDto } from './dto/create-domain-credential.dto';
import { CredentialStatusEntry } from 'src/status-list/status-list.types';

const credentialsHost = 'liccium.com';
/** DID of the platform itself: issuer of self-issued credentials and of the status list. */
export const PLATFORM_DID = `did:web:${credentialsHost}`;

/**
 * The `credentialStatus` member of a credential object, or nothing when the
 * credential gets no status-list entry. Spread after `credentialSubject`.
 */
function withCredentialStatus(credentialStatus?: CredentialStatusEntry) {
  return credentialStatus ? { credentialStatus } : {};
}

export function resolveDidKey(user: User): string {
  if (user.activeDidKeySource === 'external' && user.externalDidKey) {
    return user.externalDidKey;
  }
  return user.didKey;
}

/**
 * Returns the issuer DID derived from the issuer's verified domain or did:web.
 * This is what goes into the VC `issuer` field — it must reflect the cert holder,
 * not the platform. Falls back to the platform DID only for platform-signed VCs
 * (email, wallet, EKVC, etc.) which call `signJWTWithX5c` without an issuer cert.
 */
export function resolveMemberOf(issuer: User): string {
  if (issuer.domain) return `did:web:${issuer.domain}`;
  if (issuer.didWeb) return issuer.didWeb;
  return `urn:issuer:${issuer.id}`;
}

export function resolveIssuerDid(issuer: User): string {
  if (issuer.didWeb) return issuer.didWeb;
  if (issuer.domain) return `did:web:${issuer.domain}`;
  return PLATFORM_DID;
}

/**
 * Derives the issuer DID strictly from the CN/SAN of the issuer's X.509
 * certificate. This is the authoritative source for DataSupplier and
 * LicciumDataSupplier credentials, where the issuer field must reflect the
 * domain bound to the cert — not any user-supplied profile field.
 */
export function resolveIssuerDidFromCert(certPem: string): string {
  const cert = new crypto.X509Certificate(certPem);

  const san = cert.subjectAltName;
  if (san) {
    const dnsMatch = san.match(/DNS:([^,\s]+)/);
    if (dnsMatch) {
      const val = dnsMatch[1];
      return val.startsWith('did:web:') ? val : `did:web:${val}`;
    }
  }

  const subject = cert.subject;
  const cnMatch = subject.match(/CN=([^,\n]+)/);
  if (cnMatch) {
    const val = cnMatch[1].trim();
    return val.startsWith('did:web:') ? val : `did:web:${val}`;
  }

  return PLATFORM_DID;
}

export async function generateMembershipCredentialObjectAndJWS(
  createMemberCredentialDto: CreateMemberCredentialDto,
  creator: User,
  issuer: User,
  subjectDidKeyOverride?: string,
  credentialStatus?: CredentialStatusEntry,
) {
  const now = new Date();
  const end = new Date();
  end.setFullYear(end.getFullYear() + 3);

  const subjectDidKey = subjectDidKeyOverride ?? resolveDidKey(creator);

  const issuerCertPem =
    issuer.activeSigningCertSource === 'external' && issuer.externalCertPem
      ? issuer.externalCertPem
      : undefined;
  const issuerDid = issuerCertPem
    ? resolveIssuerDidFromCert(issuerCertPem)
    : resolveIssuerDid(issuer);

  const credentialObject = {
    '@context': ['https://www.w3.org/ns/credentials/v2'],
    id: `urn:uuid:${uuidv4()}`,
    type: [
      'VerifiableCredential',
      'VerifiableAttestation',
      'VerifiableMembership',
    ],
    issuer: issuerDid,
    validFrom: now.toISOString(),
    validUntil: end.toISOString(),
    credentialSubject: {
      id: subjectDidKey,
      memberOf: resolveMemberOf(issuer),
    },
    ...withCredentialStatus(credentialStatus),
    credentialSchema: [
      {
        id: 'https://github.com/CreatorCredentials/specifications/blob/main/json-schema/verification-credentials/member-cert-signed/schema.json',
        type: 'JsonSchema',
      },
    ],
    termsOfUse: {
      type: 'PresentationPolicy',
      confidentialityLevel: 'restricted',
      pii: 'sensitive',
    },
  };

  const jws = await signJWTWithX5c(credentialObject, issuerCertPem);

  return { credentialObject, jws };
}

// Workaround: openfuture.eu issues data-supplier credentials that must always
// target registry.commonsdb.org regardless of what value the DTO carries.
const OPENFUTURE_ISSUER_DID = 'openfuture.eu';
const OPENFUTURE_DATA_SUPPLIER_FOR = 'registry.commonsdb.org';

export async function generateDataSupplierCredentialObjectAndJWS(
  createMemberCredentialDto: CreateMemberCredentialDto,
  creator: User,
  issuer: User,
  subjectDidKeyOverride?: string,
  organizationName?: string | null,
  credentialStatus?: CredentialStatusEntry,
) {
  const now = new Date();
  const end = new Date();
  end.setFullYear(end.getFullYear() + 3);

  const subjectDidKey = subjectDidKeyOverride ?? resolveDidKey(creator);

  // The service guard already ensures externalCertPem exists before calling this
  // function, so always derive issuerDid from the cert — not from the profile.
  // activeSigningCertSource is intentionally not checked here: whatever it is set
  // to, the cert IS the authoritative signer and the VC issuer must reflect it.
  const issuerDid = resolveIssuerDidFromCert(issuer.externalCertPem);

  const dataSupplierFor = issuerDid.includes(OPENFUTURE_ISSUER_DID)
    ? OPENFUTURE_DATA_SUPPLIER_FOR
    : issuerDid;

  const credentialObject = {
    '@context': ['https://www.w3.org/ns/credentials/v2'],
    id: `urn:uuid:${uuidv4()}`,
    type: [
      'VerifiableCredential',
      'VerifiableAttestation',
      'VerifiableDataSupplier',
    ],
    issuer: issuerDid,
    validFrom: now.toISOString(),
    validUntil: end.toISOString(),
    credentialSubject: {
      id: subjectDidKey,
      dataSupplierFor,
      ...(organizationName ? { sameAs: organizationName } : {}),
    },
    ...withCredentialStatus(credentialStatus),
    credentialSchema: [
      {
        id: 'https://github.com/CreatorCredentials/specifications/blob/main/json-schema/verification-credentials/data-supplier-cert-signed/schema.json',
        type: 'JsonSchema',
      },
    ],
    termsOfUse: {
      type: 'PresentationPolicy',
      confidentialityLevel: 'public',
      pii: 'none',
    },
  };

  const jws = await signJWTWithX5c(credentialObject, issuer.externalCertPem);

  return { credentialObject, jws };
}

export async function generateLicciumDataSupplierCredentialObjectAndJWS(
  createMemberCredentialDto: CreateMemberCredentialDto,
  creator: User,
  issuer: User,
  subjectDidKeyOverride?: string,
  credentialStatus?: CredentialStatusEntry,
) {
  const now = new Date();
  const end = new Date();
  end.setFullYear(end.getFullYear() + 3);

  const subjectDidKey = subjectDidKeyOverride ?? resolveDidKey(creator);

  const issuerCertPem =
    issuer.activeSigningCertSource === 'external' && issuer.externalCertPem
      ? issuer.externalCertPem
      : undefined;
  const issuerDid = issuerCertPem
    ? resolveIssuerDidFromCert(issuerCertPem)
    : resolveIssuerDid(issuer);

  const dataSupplierFor = issuerDid.includes(OPENFUTURE_ISSUER_DID)
    ? OPENFUTURE_DATA_SUPPLIER_FOR
    : createMemberCredentialDto.value;

  const credentialObject = {
    '@context': ['https://www.w3.org/ns/credentials/v2'],
    id: `urn:uuid:${uuidv4()}`,
    type: [
      'VerifiableCredential',
      'VerifiableAttestation',
      'VerifiableDataSupplier',
    ],
    issuer: issuerDid,
    validFrom: now.toISOString(),
    validUntil: end.toISOString(),
    credentialSubject: {
      id: subjectDidKey,
      dataSupplierFor,
    },
    ...withCredentialStatus(credentialStatus),
    credentialSchema: [
      {
        id: 'https://github.com/CreatorCredentials/specifications/blob/main/json-schema/verification-credentials/data-supplier-cert-signed/schema.json',
        type: 'JsonSchema',
      },
    ],
    termsOfUse: {
      type: 'PresentationPolicy',
      confidentialityLevel: 'public',
      pii: 'none',
    },
  };

  const jws = await signJWTWithX5c(credentialObject, issuerCertPem);

  return { credentialObject, jws };
}

export async function generateExternalKeypairVerificationCredentialObjectAndJWS(
  user: User,
  derivedDidKey: string,
  email: string,
  organizationName?: string | null,
  credentialStatus?: CredentialStatusEntry,
) {
  const now = new Date();
  const end = new Date();
  end.setFullYear(end.getFullYear() + 3);

  const credentialObject = {
    '@context': ['https://www.w3.org/ns/credentials/v2'],
    id: `urn:uuid:${uuidv4()}`,
    type: [
      'VerifiableCredential',
      'VerifiableAttestation',
      'ExternalKeypairVerification',
    ],
    issuer: PLATFORM_DID,
    validFrom: now.toISOString(),
    validUntil: end.toISOString(),
    credentialSubject: {
      email,
      sameAs: derivedDidKey,
      ...(organizationName ? { organizationName } : {}),
    },
    ...withCredentialStatus(credentialStatus),
    credentialSchema: [
      {
        id: 'https://github.com/CreatorCredentials/specifications/blob/main/json-schema/verification-credentials/external-keypair/schema.json',
        type: 'JsonSchema',
      },
    ],
    termsOfUse: {
      type: 'PresentationPolicy',
      confidentialityLevel: 'restricted',
      pii: 'sensitive',
    },
  };

  const jws = await signJWTWithX5c(credentialObject);

  return { credentialObject, jws };
}

export async function generateEmailCredentialObjectAndJWS(
  createEmailCredentialDto: CreateEmailCredentialDto,
  user: User,
  credentialStatus?: CredentialStatusEntry,
) {
  const now = new Date();
  const end = new Date();
  end.setFullYear(end.getFullYear() + 3);

  const credentialObject = {
    '@context': ['https://www.w3.org/ns/credentials/v2'],
    id: `urn:uuid:${uuidv4()}`,
    type: ['VerifiableCredential', 'VerifiableAttestation', 'VerifiableEmail'],
    issuer: PLATFORM_DID,
    validFrom: now.toISOString(),
    validUntil: end.toISOString(),
    credentialSubject: {
      id: resolveDidKey(user),
      email: createEmailCredentialDto.email,
    },
    ...withCredentialStatus(credentialStatus),
    credentialSchema: [
      {
        id: 'https://github.com/CreatorCredentials/specifications/blob/main/json-schema/verification-credentials/email/schema.json',
        type: 'JsonSchema',
      },
    ],
    termsOfUse: {
      type: 'PresentationPolicy',
      confidentialityLevel: 'restricted',
      pii: 'sensitive',
    },
  };

  const jws = await signJWTWithX5c(credentialObject);

  return { credentialObject, jws };
}

/**
 * Platform-issued attestation that the creator's Liccium account is linked.
 * The subject carries no personal data, so the presentation policy is public.
 */
export function buildCreatorCredentialObject(
  user: User,
  verifiedBy: string,
  credentialStatus?: CredentialStatusEntry,
) {
  const now = new Date();
  const end = new Date();
  end.setFullYear(end.getFullYear() + 3);

  return {
    '@context': ['https://www.w3.org/ns/credentials/v2'],
    id: `urn:uuid:${uuidv4()}`,
    type: [
      'VerifiableCredential',
      'VerifiableAttestation',
      'VerifiableCreator',
    ],
    issuer: PLATFORM_DID,
    validFrom: now.toISOString(),
    validUntil: end.toISOString(),
    credentialSubject: {
      id: resolveDidKey(user),
      verifiedBy,
    },
    ...withCredentialStatus(credentialStatus),
    credentialSchema: [
      {
        id: 'https://raw.githubusercontent.com/CreatorCredentials/specifications/main/json-schema/verification-credentials/creator/schema.json',
        type: 'JsonSchema',
      },
    ],
    termsOfUse: {
      type: 'PresentationPolicy',
      confidentialityLevel: 'public',
      pii: 'none',
    },
  };
}

export async function generateCreatorCredentialObjectAndJWS(
  user: User,
  verifiedBy: string,
  credentialStatus?: CredentialStatusEntry,
) {
  const credentialObject = buildCreatorCredentialObject(
    user,
    verifiedBy,
    credentialStatus,
  );
  const jws = await signJWTWithX5c(credentialObject);

  return { credentialObject, jws };
}

export async function generateDomainCredentialObjectAndJWS(
  createDomainCredentialDto: CreateDomainCredentialDto,
  user: User,
  credentialStatus?: CredentialStatusEntry,
) {
  const now = new Date();
  const end = new Date();
  end.setFullYear(end.getFullYear() + 3);

  const credentialObject = {
    '@context': ['https://www.w3.org/ns/credentials/v2'],
    id: `urn:uuid:${uuidv4()}`,
    type: ['VerifiableCredential', 'VerifiableAttestation', 'VerifiableDomain'],
    issuer: PLATFORM_DID,
    validFrom: now.toISOString(),
    validUntil: end.toISOString(),
    credentialSubject: {
      id: resolveDidKey(user),
      domain: createDomainCredentialDto.domain,
    },
    ...withCredentialStatus(credentialStatus),
    credentialSchema: [
      {
        id: 'https://github.com/CreatorCredentials/specifications/blob/main/json-schema/verification-credentials/domain/schema.json',
        type: 'JsonSchema',
      },
    ],
    termsOfUse: {
      type: 'PresentationPolicy',
      confidentialityLevel: 'restricted',
      pii: 'sensitive',
    },
  };

  const jws = await signJWTWithX5c(credentialObject);

  return { credentialObject, jws };
}

export async function generateConnectCredentialObjectAndJWS(
  createConnectCredentialDto: CreateConnectCredentialDto,
  credentialStatus?: CredentialStatusEntry,
) {
  const now = new Date();
  const end = new Date();
  end.setFullYear(end.getFullYear() + 3);

  const credentialObject = {
    '@context': ['https://www.w3.org/ns/credentials/v2'],
    id: `urn:uuid:${uuidv4()}`,
    type: [
      'VerifiableCredential',
      'VerifiableAttestation',
      'VerifiableDidConnect',
    ],
    issuer: PLATFORM_DID,
    validFrom: now.toISOString(),
    validUntil: end.toISOString(),
    credentialSubject: {
      id: createConnectCredentialDto.didKey,
      sameAs: createConnectCredentialDto.licciumDidKey,
    },
    ...withCredentialStatus(credentialStatus),
    credentialSchema: [
      {
        id: 'https://github.com/CreatorCredentials/specifications/blob/main/json-schema/verification-credentials/email/schema.json',
        type: 'JsonSchema',
      },
    ],
    termsOfUse: {
      type: 'PresentationPolicy',
      confidentialityLevel: 'restricted',
      pii: 'sensitive',
    },
  };
  const jws = await signJWTWithX5c(credentialObject);

  return { credentialObject, jws };
}

// Function to load DER file
async function loadDerFile(certFilePath) {
  try {
    // Read DER file
    const certDER = await fs.promises.readFile(certFilePath);
    return certDER;
  } catch (error) {
    console.error('Error loading DER file:', error);
    throw error;
  }
}
// Function to encode DER as Base64
function derToBase64(derBuffer) {
  try {
    // Encode DER as Base64
    const base64Data = derBuffer.toString('base64');
    return base64Data;
  } catch (error) {
    console.error('Error encoding DER as Base64:', error);
    throw error;
  }
}
// Function to sign JWT with x5c header claim
// If issuerCertPem is provided it is used in x5c instead of the platform cert
export async function signJWTWithX5c(payload, issuerCertPem?: string) {
  try {
    const privateKeyPEM = process.env.HALCOM_CERT_PRIVATE_KEY.replaceAll(
      '\\n',
      '\n',
    );

    let certB64: string;
    if (issuerCertPem) {
      // Strip PEM headers/footers and whitespace — what remains is base64-encoded DER
      certB64 = issuerCertPem
        .replace(/-----BEGIN CERTIFICATE-----/, '')
        .replace(/-----END CERTIFICATE-----/, '')
        .replace(/\s/g, '');
    } else {
      const certDER = await loadDerFile('./certificates/LICCIUM.der');
      certB64 = derToBase64(certDER);
    }

    const signedJWT = jwt.sign(payload, privateKeyPEM, {
      algorithm: 'RS256',
      header: {
        x5c: [certB64],
      },
    });

    return signedJWT;
  } catch (error) {
    console.error('Error signing JWT with x5c header claim:', error);
    throw error;
  }
}
