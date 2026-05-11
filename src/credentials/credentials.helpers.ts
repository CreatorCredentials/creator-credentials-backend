import * as jose from 'jose';
import * as fs from 'fs';
import { v4 as uuidv4 } from 'uuid';
import { CreateMemberCredentialDto } from './dto/create-member-credential.dto';
import { User } from 'src/users/user.entity';
import { NotFoundException } from '@nestjs/common';
import * as jwt from 'jsonwebtoken';
import { CreateEmailCredentialDto } from './dto/create-email-credential.dto';
import { CreateConnectCredentialDto } from './dto/create-connect-credential.dto';
import { CreateDomainCredentialDto } from './dto/create-domain-credential.dto';

const credentialsHost = 'liccium.com';

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
export function resolveIssuerDid(issuer: User): string {
  if (issuer.didWeb) return issuer.didWeb;
  if (issuer.domain) return `did:web:${issuer.domain}`;
  return `did:web:${credentialsHost}`;
}

export async function generateMembershipCredentialObjectAndJWS(
  createMemberCredentialDto: CreateMemberCredentialDto,
  creator: User,
  issuer: User,
  subjectDidKeyOverride?: string,
) {
  const now = new Date();
  const end = new Date();
  end.setFullYear(end.getFullYear() + 1);

  const subjectDidKey = subjectDidKeyOverride ?? resolveDidKey(creator);

  const credentialObject = {
    '@context': ['https://www.w3.org/ns/credentials/v2'],
    id: `urn:uuid:${uuidv4()}`,
    type: [
      'VerifiableCredential',
      'VerifiableAttestation',
      'VerifiableMembership',
    ],
    issuer: resolveIssuerDid(issuer),
    validFrom: now.toISOString(),
    validUntil: end.toISOString(),
    credentialSubject: {
      id: subjectDidKey,
      memberOf: `urn:issuer:${issuer.id}`,
    },
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

  const issuerCertPem =
    issuer.activeSigningCertSource === 'external' && issuer.externalCertPem
      ? issuer.externalCertPem
      : undefined;
  const jws = await signJWTWithX5c(credentialObject, issuerCertPem);

  return { credentialObject, jws };
}

export async function generateDataSupplierCredentialObjectAndJWS(
  createMemberCredentialDto: CreateMemberCredentialDto,
  creator: User,
  issuer: User,
  subjectDidKeyOverride?: string,
) {
  const now = new Date();
  const end = new Date();
  end.setFullYear(end.getFullYear() + 1);

  const subjectDidKey = subjectDidKeyOverride ?? resolveDidKey(creator);

  const credentialObject = {
    '@context': ['https://www.w3.org/ns/credentials/v2'],
    id: `urn:uuid:${uuidv4()}`,
    type: [
      'VerifiableCredential',
      'VerifiableAttestation',
      'VerifiableDataSupplier',
    ],
    issuer: resolveIssuerDid(issuer),
    validFrom: now.toISOString(),
    validUntil: end.toISOString(),
    credentialSubject: {
      id: subjectDidKey,
      dataSupplierFor: createMemberCredentialDto.value,
    },
    credentialSchema: [
      {
        id: 'https://github.com/CreatorCredentials/specifications/blob/main/json-schema/verification-credentials/data-supplier-cert-signed/schema.json',
        type: 'JsonSchema',
      },
    ],
    termsOfUse: {
      type: 'PresentationPolicy',
      confidentialityLevel: 'restricted',
      pii: 'sensitive',
    },
  };

  const issuerCertPem =
    issuer.activeSigningCertSource === 'external' && issuer.externalCertPem
      ? issuer.externalCertPem
      : undefined;
  const jws = await signJWTWithX5c(credentialObject, issuerCertPem);

  return { credentialObject, jws };
}

export async function generateExternalKeypairVerificationCredentialObjectAndJWS(
  user: User,
  derivedDidKey: string,
  email: string,
) {
  const now = new Date();
  const end = new Date();
  end.setFullYear(end.getFullYear() + 1);

  const credentialObject = {
    '@context': ['https://www.w3.org/ns/credentials/v2'],
    id: `urn:uuid:${uuidv4()}`,
    type: [
      'VerifiableCredential',
      'VerifiableAttestation',
      'ExternalKeypairVerification',
    ],
    issuer: `did:web:${credentialsHost}`,
    validFrom: now.toISOString(),
    validUntil: end.toISOString(),
    credentialSubject: {
      email,
      sameAs: derivedDidKey,
    },
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
) {
  const now = new Date();
  const end = new Date();
  end.setFullYear(end.getFullYear() + 1);

  const credentialObject = {
    '@context': ['https://www.w3.org/ns/credentials/v2'],
    id: `urn:uuid:${uuidv4()}`,
    type: ['VerifiableCredential', 'VerifiableAttestation', 'VerifiableEmail'],
    issuer: `did:web:${credentialsHost}`,
    validFrom: now.toISOString(),
    validUntil: end.toISOString(),
    credentialSubject: {
      id: resolveDidKey(user),
      email: createEmailCredentialDto.email,
    },
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

export async function generateDomainCredentialObjectAndJWS(
  createDomainCredentialDto: CreateDomainCredentialDto,
  user: User,
) {
  const now = new Date();
  const end = new Date();
  end.setFullYear(end.getFullYear() + 1);

  const credentialObject = {
    '@context': ['https://www.w3.org/ns/credentials/v2'],
    id: `urn:uuid:${uuidv4()}`,
    type: ['VerifiableCredential', 'VerifiableAttestation', 'VerifiableDomain'],
    issuer: `did:web:${credentialsHost}`,
    validFrom: now.toISOString(),
    validUntil: end.toISOString(),
    credentialSubject: {
      id: resolveDidKey(user),
      domain: createDomainCredentialDto.domain,
    },
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
) {
  const now = new Date();
  const end = new Date();
  end.setFullYear(end.getFullYear() + 1);

  const credentialObject = {
    '@context': ['https://www.w3.org/ns/credentials/v2'],
    id: `urn:uuid:${uuidv4()}`,
    type: [
      'VerifiableCredential',
      'VerifiableAttestation',
      'VerifiableDidConnect',
    ],
    issuer: `did:web:${credentialsHost}`,
    validFrom: now.toISOString(),
    validUntil: end.toISOString(),
    credentialSubject: {
      id: createConnectCredentialDto.didKey,
      sameAs: createConnectCredentialDto.licciumDidKey,
    },
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
