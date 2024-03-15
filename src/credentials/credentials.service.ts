import {
  ConflictException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { DeleteResult, Repository } from 'typeorm';
import { CreateEmailCredentialDto } from './dto/create-email-credential.dto';
import {
  Credential,
  CredentialType,
  CredentialVerificationStatus,
} from './credential.entity';
import * as jose from 'jose';
import { User } from 'src/users/user.entity';
import { v4 as uuidv4 } from 'uuid';
import { formatCredential } from './credentials.utils';
import { CreateWalletCredentialDto } from './dto/create-wallet-credential.dto';
import { CreateDomainCredentialDto } from './dto/create-domain-credential.dto';
import { CreateDidWebCredentialDto } from './dto/create-didweb-credential.dto';

@Injectable()
export class CredentialsService {
  constructor(
    @InjectRepository(Credential)
    private credentialsRepository: Repository<Credential>,
  ) {}

  async getById(id: number, clerkId: string): Promise<Credential> {
    return this.credentialsRepository.findOne({
      where: { id, user: { clerkId } },
    });
  }

  async getEmailCredentialOfUser(user: User): Promise<Credential[]> {
    const credential = await this.credentialsRepository.findOne({
      where: { userId: user.id, credentialType: CredentialType.EMail },
    });

    return credential && formatCredential(credential);
  }

  async getWalletCredentialOfUser(user: User): Promise<Credential[]> {
    const credential = await this.credentialsRepository.findOne({
      where: { userId: user.id, credentialType: CredentialType.Wallet },
    });

    return credential && formatCredential(credential);
  }

  async getDomainCredentialOfUser(user: User): Promise<Credential[]> {
    const credential = await this.credentialsRepository.findOne({
      where: { userId: user.id, credentialType: CredentialType.Domain },
    });

    return credential && formatCredential(credential);
  }

  async getDidWebCredentialOfUser(user: User): Promise<Credential[]> {
    const credential = await this.credentialsRepository.findOne({
      where: { userId: user.id, credentialType: CredentialType.DidWeb },
    });

    return credential && formatCredential(credential);
  }

  async getAllCredentialsOfUser(user: User): Promise<Credential[]> {
    const credentials = await this.credentialsRepository.find({
      where: { userId: user.id },
    });

    return credentials.map(formatCredential);
  }

  async removeEmailCredential(user: User): Promise<DeleteResult> {
    const credential = await this.credentialsRepository.findOne({
      where: { userId: user.id, credentialType: CredentialType.EMail },
    });

    return this.credentialsRepository.delete({ id: credential?.id });
  }
  async removeWalletCredential(user: User): Promise<DeleteResult> {
    const credential = await this.credentialsRepository.findOne({
      where: { userId: user.id, credentialType: CredentialType.Wallet },
    });

    return this.credentialsRepository.delete({ id: credential?.id });
  }
  async removeDomainCredential(user: User): Promise<DeleteResult> {
    const credential = await this.credentialsRepository.findOne({
      where: { userId: user.id, credentialType: CredentialType.Domain },
    });

    return this.credentialsRepository.delete({ id: credential?.id });
  }

  async removeDidWebCredential(user: User): Promise<DeleteResult> {
    const credential = await this.credentialsRepository.findOne({
      where: { userId: user.id, credentialType: CredentialType.DidWeb },
    });

    return this.credentialsRepository.delete({ id: credential?.id });
  }

  async createWalletCredential(
    createWalletCredentialDto: CreateWalletCredentialDto,
    user: User,
  ): Promise<Credential> {
    const credentialsHost = 'creatorcredentials.dev';

    const currentWalletCredential = await this.credentialsRepository.findOne({
      where: { credentialType: CredentialType.Wallet, userId: user.id },
    });

    if (currentWalletCredential) {
      throw new ConflictException(
        'Wallet credential already exists for this user.',
      );
    }

    const now = new Date();
    const end = new Date();
    end.setFullYear(end.getFullYear() + 1);

    const credentialObject = {
      '@context': ['https://www.w3.org/ns/credentials/v2'],
      id: `urn:uuid:${uuidv4()}`,
      type: [
        'VerifiableCredential',
        'VerifiableAttestation',
        'VerifiableWallet',
      ],
      issuer: `did:web:${credentialsHost}`,
      validFrom: now.toISOString(),
      validUntil: end.toISOString(),
      credentialSubject: {
        id: `did:key:${createWalletCredentialDto.did}`,
        walletAddress: createWalletCredentialDto.publicAddress,
      },
      credentialSchema: [
        {
          id: 'https://github.com/CreatorCredentials/specifications/blob/main/json-schema/verification-credentials/wallet/schema.json',
          type: 'JsonSchema',
        },
      ],
      termsOfUse: {
        type: 'PresentationPolicy',
        confidentialityLevel: 'restricted',
        pii: 'sensitive',
      },
    };

    const ecPrivateKey = await jose.importJWK(
      {
        kty: 'EC',
        crv: 'P-256',
        d: process.env.SIGNATURE_KEY_D,
        x: process.env.SIGNATURE_KEY_X,
        y: process.env.SIGNATURE_KEY_Y,
      },
      'ES256',
    );
    const jws = await new jose.CompactSign(
      new TextEncoder().encode(JSON.stringify(credentialObject)),
    )
      .setProtectedHeader({ alg: 'ES256' })
      .sign(ecPrivateKey);

    const credential = await this.credentialsRepository.create({
      email: createWalletCredentialDto.publicAddress,
      credentialType: CredentialType.Wallet,
      credentialObject,
      credentialStatus: CredentialVerificationStatus.Success,
      token: jws,
      user,
    });

    await this.credentialsRepository.save(credential, { reload: true });

    const result = credential.credentialObject;
    result.proof = {
      type: 'JwtProof2020',
      jwt: jws,
    };
    return result;
  }

  async createEmailCredential(
    createEmailCredentialDto: CreateEmailCredentialDto,
    user: User,
  ): Promise<Credential> {
    const credentialsHost = 'creatorcredentials.dev';

    const currentEmailCredential = await this.credentialsRepository.findOne({
      where: { credentialType: CredentialType.EMail, userId: user.id },
    });

    if (currentEmailCredential) {
      throw new ConflictException(
        'Email credential already exists for this user.',
      );
    }

    const now = new Date();
    const end = new Date();
    end.setFullYear(end.getFullYear() + 1);

    const credentialObject = {
      '@context': ['https://www.w3.org/ns/credentials/v2'],
      id: `urn:uuid:${uuidv4()}`,
      type: [
        'VerifiableCredential',
        'VerifiableAttestation',
        'VerifiableEmail',
      ],
      issuer: `did:web:${credentialsHost}`,
      validFrom: now.toISOString(),
      validUntil: end.toISOString(),
      credentialSubject: {
        id: `did:key:${createEmailCredentialDto.did}`,
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

    const ecPrivateKey = await jose.importJWK(
      {
        kty: 'EC',
        crv: 'P-256',
        d: process.env.SIGNATURE_KEY_D,
        x: process.env.SIGNATURE_KEY_X,
        y: process.env.SIGNATURE_KEY_Y,
      },
      'ES256',
    );
    const jws = await new jose.CompactSign(
      new TextEncoder().encode(JSON.stringify(credentialObject)),
    )
      .setProtectedHeader({ alg: 'ES256' })
      .sign(ecPrivateKey);

    const credential = await this.credentialsRepository.create({
      email: createEmailCredentialDto.email,
      credentialType: CredentialType.EMail,
      credentialObject,
      credentialStatus: CredentialVerificationStatus.Success,
      token: jws,
      user,
    });

    await this.credentialsRepository.save(credential, { reload: true });

    const result = credential.credentialObject;
    result.proof = {
      type: 'JwtProof2020',
      jwt: jws,
    };
    return result;
  }

  async createPendingDomainCredential(
    createDomainCredentialDto: CreateDomainCredentialDto,
    user: User,
  ): Promise<Credential> {
    const credential = await this.credentialsRepository.create({
      email: createDomainCredentialDto.domain,
      credentialType: CredentialType.Domain,
      credentialStatus: CredentialVerificationStatus.Pending,
      credentialObject: {},
      token: '',
      user,
    });

    return await this.credentialsRepository.save(credential, { reload: true });
  }

  async createDomainCredential(
    createDomainCredentialDto: CreateDomainCredentialDto,
    user: User,
  ): Promise<Credential> {
    const credentialsHost = 'creatorcredentials.dev';

    const currentDomainCredential = await this.credentialsRepository.findOne({
      where: { credentialType: CredentialType.Domain, userId: user.id },
    });

    if (
      currentDomainCredential &&
      currentDomainCredential.credentialStatus ===
        CredentialVerificationStatus.Success
    ) {
      throw new ConflictException(
        'Domain credential already exists for this user.',
      );
    } else {
      await this.removeDomainCredential(user);
    }

    const now = new Date();
    const end = new Date();
    end.setFullYear(end.getFullYear() + 1);

    const credentialObject = {
      '@context': ['https://www.w3.org/ns/credentials/v2'],
      id: `urn:uuid:${uuidv4()}`,
      type: [
        'VerifiableCredential',
        'VerifiableAttestation',
        'VerifiableDomain',
      ],
      issuer: `did:web:${credentialsHost}`,
      validFrom: now.toISOString(),
      validUntil: end.toISOString(),
      credentialSubject: {
        id: `did:key:${createDomainCredentialDto.did}`,
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

    const ecPrivateKey = await jose.importJWK(
      {
        kty: 'EC',
        crv: 'P-256',
        d: process.env.SIGNATURE_KEY_D,
        x: process.env.SIGNATURE_KEY_X,
        y: process.env.SIGNATURE_KEY_Y,
      },
      'ES256',
    );
    const jws = await new jose.CompactSign(
      new TextEncoder().encode(JSON.stringify(credentialObject)),
    )
      .setProtectedHeader({ alg: 'ES256' })
      .sign(ecPrivateKey);

    const credential = await this.credentialsRepository.create({
      email: createDomainCredentialDto.domain,
      credentialType: CredentialType.Domain,
      credentialStatus: CredentialVerificationStatus.Success,
      credentialObject,
      token: jws,
      user,
    });

    await this.credentialsRepository.save(credential, { reload: true });

    const result = credential.credentialObject;
    result.proof = {
      type: 'JwtProof2020',
      jwt: jws,
    };
    return result;
  }

  async createPendingDidWebCredential(
    createDidWebCredentialDto: CreateDidWebCredentialDto,
    user: User,
  ): Promise<Credential> {
    const credential = await this.credentialsRepository.create({
      email: createDidWebCredentialDto.didWeb,
      credentialType: CredentialType.DidWeb,
      credentialStatus: CredentialVerificationStatus.Pending,
      credentialObject: {},
      token: '',
      user,
    });

    return await this.credentialsRepository.save(credential, { reload: true });
  }

  async createDidWebCredential(
    createDidWebCredentialDto: CreateDidWebCredentialDto,
    user: User,
  ): Promise<Credential> {
    const credentialsHost = 'creatorcredentials.dev';

    const currentDidWebCredential = await this.credentialsRepository.findOne({
      where: { credentialType: CredentialType.DidWeb, userId: user.id },
    });

    if (
      currentDidWebCredential &&
      currentDidWebCredential.credentialStatus ===
        CredentialVerificationStatus.Success
    ) {
      throw new ConflictException(
        'Domain credential already exists for this user.',
      );
    } else {
      await this.removeDidWebCredential(user);
    }

    const now = new Date();
    const end = new Date();
    end.setFullYear(end.getFullYear() + 1);

    const credentialObject = {
      '@context': ['https://www.w3.org/ns/credentials/v2'],
      id: `urn:uuid:${uuidv4()}`,
      type: [
        'VerifiableCredential',
        'VerifiableAttestation',
        'VerifiableDomain',
      ],
      issuer: `did:web:${credentialsHost}`,
      validFrom: now.toISOString(),
      validUntil: end.toISOString(),
      credentialSubject: {
        id: `did:key:${createDidWebCredentialDto.did}`,
        didWeb: createDidWebCredentialDto.didWeb,
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

    const ecPrivateKey = await jose.importJWK(
      {
        kty: 'EC',
        crv: 'P-256',
        d: process.env.SIGNATURE_KEY_D,
        x: process.env.SIGNATURE_KEY_X,
        y: process.env.SIGNATURE_KEY_Y,
      },
      'ES256',
    );
    const jws = await new jose.CompactSign(
      new TextEncoder().encode(JSON.stringify(credentialObject)),
    )
      .setProtectedHeader({ alg: 'ES256' })
      .sign(ecPrivateKey);

    const credential = await this.credentialsRepository.create({
      email: createDidWebCredentialDto.didWeb,
      credentialType: CredentialType.DidWeb,
      credentialStatus: CredentialVerificationStatus.Success,
      credentialObject,
      token: jws,
      user,
    });

    await this.credentialsRepository.save(credential, { reload: true });

    const result = credential.credentialObject;
    result.proof = {
      type: 'JwtProof2020',
      jwt: jws,
    };
    return result;
  }
}
