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

export async function generateMemberCredentialObjectAndJWS(
  createMemberCredentialDto: CreateMemberCredentialDto,
  creator: User,
) {
  const now = new Date();
  const end = new Date();
  end.setFullYear(end.getFullYear() + 1);

  const credentialObject = {
    '@context': ['https://www.w3.org/ns/credentials/v2'],
    id: `urn:uuid:${uuidv4()}`,
    type: ['VerifiableCredential', 'VerifiableAttestation', 'VerifiableMember'],
    issuer: `did:web:${credentialsHost}`,
    validFrom: now.toISOString(),
    validUntil: end.toISOString(),
    credentialSubject: {
      id: `${creator.didKey}`,
      memberOf: `did:web:${createMemberCredentialDto.value}`,
    },
    credentialSchema: [
      {
        id: 'https://github.com/CreatorCredentials/specifications/blob/main/json-schema/verification-credentials/member/schema.json',
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
      id: user.didKey,
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
      id: `${user.didKey}`,
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
export async function signJWTWithX5c(payload) {
  try {
    const privateKeyPEM = process.env.HALCOM_CERT_PRIVATE_KEY.replaceAll(
      '\\n',
      '\n',
    );
    const certFilePath = './certificates/LICCIUM.der'; // Path to the certificate file

    // Read the X.509 certificate from DER file
    const certDER = await loadDerFile(certFilePath);
    const certB64 = derToBase64(certDER);

    // Sign JWT using the private key and add x5c header claim
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
