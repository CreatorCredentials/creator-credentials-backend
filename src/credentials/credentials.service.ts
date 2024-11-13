import { ConflictException, Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { ArrayContains, DeleteResult, Repository } from 'typeorm';
import { CreateEmailCredentialDto } from './dto/create-email-credential.dto';
import { Credential } from './credential.entity';
import * as jose from 'jose';
import { User } from 'src/users/user.entity';
import { v4 as uuidv4 } from 'uuid';
import { CreateWalletCredentialDto } from './dto/create-wallet-credential.dto';
import { CreateDomainCredentialDto } from './dto/create-domain-credential.dto';
import { CreateDidWebCredentialDto } from './dto/create-didweb-credential.dto';
import { CredentialType } from 'src/shared/typings/CredentialType';
import { CredentialVerificationStatus } from 'src/shared/typings/CredentialVerificationStatus';
import { CreateMemberCredentialDto } from './dto/create-member-credential.dto';
import {
  generateConnectCredentialObjectAndJWS,
  generateDomainCredentialObjectAndJWS,
  generateEmailCredentialObjectAndJWS,
  generateMemberCredentialObjectAndJWS,
} from './credentials.helpers';
import { CreateConnectCredentialDto } from './dto/create-connect-credential.dto';

const credentialsHost = 'liccium.com';

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

  async getAllIssuersMemberCredentialsWithCreators(
    issuerId: number,
    status: CredentialVerificationStatus = CredentialVerificationStatus.Success,
  ): Promise<Credential[]> {
    const credentials = await this.credentialsRepository.find({
      where: { issuerId, credentialStatus: status },
      relations: ['user'],
    });

    return credentials;
  }

  async getCredentialsOfUserByType(
    user: User,
    credentialType: CredentialType,
  ): Promise<Credential[]> {
    const credential = await this.credentialsRepository.find({
      where: { userId: user.id, credentialType },
      relations: ['issuer'],
    });

    return credential;
  }

  async getAllCredentialsOfUser(user: User): Promise<Credential[]> {
    const credentials = await this.credentialsRepository.find({
      where: { userId: user.id },
    });

    return credentials;
  }

  async removeEmailCredential(user: User): Promise<DeleteResult> {
    const credential = await this.credentialsRepository.findOne({
      where: { userId: user.id, credentialType: CredentialType.EMail },
    });

    return this.credentialsRepository.delete({ id: credential?.id });
  }

  async removeConnectCredential(user: User): Promise<DeleteResult> {
    const credential = await this.credentialsRepository.findOne({
      where: { userId: user.id, credentialType: CredentialType.Connect },
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

  async removeMemberCredential(credentialId: number): Promise<DeleteResult> {
    return this.deleteCredential(credentialId);
  }

  async deleteCredential(credentialId: number): Promise<DeleteResult> {
    return this.credentialsRepository.delete({ id: credentialId });
  }

  async createWalletCredential(
    createWalletCredentialDto: CreateWalletCredentialDto,
    user: User,
  ): Promise<Credential> {
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
        id: `${user.didKey}`,
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
    const currentEmailCredential = await this.credentialsRepository.findOne({
      where: { credentialType: CredentialType.EMail, userId: user.id },
    });

    if (currentEmailCredential) {
      throw new ConflictException(
        'Email credential already exists for this user.',
      );
    }

    const { credentialObject, jws } = await generateEmailCredentialObjectAndJWS(
      createEmailCredentialDto,
      user,
    );
    // const ecPrivateKey = await jose.importJWK(
    //   {
    //     kty: 'EC',
    //     crv: 'P-256',
    //     d: process.env.SIGNATURE_KEY_D,
    //     x: process.env.SIGNATURE_KEY_X,
    //     y: process.env.SIGNATURE_KEY_Y,
    //   },
    //   'ES256',
    // );
    // const jws = await new jose.CompactSign(
    //   new TextEncoder().encode(JSON.stringify(credentialObject)),
    // )
    //   .setProtectedHeader({ alg: 'ES256' })
    //   .sign(ecPrivateKey);

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

  async createConnectCredential(
    createConnectCredentialDto: CreateConnectCredentialDto,
    user: User,
  ): Promise<Credential> {
    const currentConnectCredential = await this.credentialsRepository.findOne({
      where: { credentialType: CredentialType.Connect, userId: user.id },
    });

    if (currentConnectCredential) {
      await this.removeConnectCredential(user);
      // throw new ConflictException(
      //   'Connect credential already exists for this user.',
      // );
    }

    const { credentialObject, jws } =
      await generateConnectCredentialObjectAndJWS(createConnectCredentialDto);

    // const ecPrivateKey = await jose.importJWK(
    //   {
    //     kty: 'EC',
    //     crv: 'P-256',
    //     d: process.env.SIGNATURE_KEY_D,
    //     x: process.env.SIGNATURE_KEY_X,
    //     y: process.env.SIGNATURE_KEY_Y,
    //   },
    //   'ES256',
    // );
    // const jws = await new jose.CompactSign(
    //   new TextEncoder().encode(JSON.stringify(credentialObject)),
    // )
    //   .setProtectedHeader({ alg: 'ES256' })
    //   .sign(ecPrivateKey);

    const credential = await this.credentialsRepository.create({
      email: createConnectCredentialDto.licciumDidKey,
      credentialType: CredentialType.Connect,
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

    const { credentialObject, jws } =
      await generateDomainCredentialObjectAndJWS(
        createDomainCredentialDto,
        user,
      );

    // const ecPrivateKey = await jose.importJWK(
    //   {
    //     kty: 'EC',
    //     crv: 'P-256',
    //     d: process.env.SIGNATURE_KEY_D,
    //     x: process.env.SIGNATURE_KEY_X,
    //     y: process.env.SIGNATURE_KEY_Y,
    //   },
    //   'ES256',
    // );
    // const jws = await new jose.CompactSign(
    //   new TextEncoder().encode(JSON.stringify(credentialObject)),
    // )
    //   .setProtectedHeader({ alg: 'ES256' })
    //   .sign(ecPrivateKey);

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
        'VerifiableDidWeb',
      ],
      issuer: `did:web:${credentialsHost}`,
      validFrom: now.toISOString(),
      validUntil: end.toISOString(),
      credentialSubject: {
        id: `${user.didKey}`,
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

  async createPendingMemberCredential(
    createMemberCredentialDto: CreateMemberCredentialDto,
    user: User,
    issuerId: number,
  ): Promise<Credential> {
    // TODO prevent creation of new pending credential if credential exists at pending
    // or accepted state for the same creator and issuer pair

    const currentMemberCredential = await this.credentialsRepository.findOne({
      where: {
        credentialType: CredentialType.Member,
        issuerId,
        userId: user.id,
      },
      relations: ['user'],
    });

    if (currentMemberCredential) {
      throw new ConflictException(
        'Member credential of that issue is already requested by that user.',
      );
    }

    const credential = this.credentialsRepository.create({
      email: createMemberCredentialDto.value,
      value: createMemberCredentialDto.value,
      issuerId,
      credentialType: CredentialType.Member,
      credentialStatus: CredentialVerificationStatus.Pending,
      credentialObject: {},
      token: '',
      user,
    });

    return await this.credentialsRepository.save(credential, { reload: true });
  }

  async createMemberCredential(
    issuer: User,
    credentialId: number,
  ): Promise<Credential> {
    const currentPendingMemberCredential =
      await this.credentialsRepository.findOne({
        where: {
          credentialType: CredentialType.Member,
          issuerId: issuer.id,
          id: credentialId,
          credentialStatus: CredentialVerificationStatus.Pending,
        },
        relations: ['user'],
      });

    if (!currentPendingMemberCredential) {
      throw new ConflictException(
        'Member credential was not requested by user from this issuer.',
      );
    }

    const { credentialObject, jws } =
      await generateMemberCredentialObjectAndJWS(
        {
          value: currentPendingMemberCredential.value,
          did: currentPendingMemberCredential.user.didKey,
        },
        currentPendingMemberCredential.user,
      );

    const credential = currentPendingMemberCredential;

    credential.credentialStatus = CredentialVerificationStatus.Success;
    credential.credentialObject = credentialObject;
    credential.token = jws;

    await this.credentialsRepository.save(credential, { reload: true });

    const result = credential.credentialObject;
    result.proof = {
      type: 'JwtProof2020',
      jwt: jws,
    };
    return result;
  }
}
