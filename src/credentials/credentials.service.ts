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
  generateDataSupplierCredentialObjectAndJWS,
  generateLicciumDataSupplierCredentialObjectAndJWS,
  generateDomainCredentialObjectAndJWS,
  generateEmailCredentialObjectAndJWS,
  generateExternalKeypairVerificationCredentialObjectAndJWS,
  generateMembershipCredentialObjectAndJWS,
  resolveDidKey,
} from './credentials.helpers';
import { CreateConnectCredentialDto } from './dto/create-connect-credential.dto';
import * as crypto from 'crypto';

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
    end.setFullYear(end.getFullYear() + 3);

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
        id: resolveDidKey(user),
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
    const existingPending = await this.credentialsRepository.findOne({
      where: {
        credentialType: CredentialType.DidWeb,
        userId: user.id,
        credentialStatus: CredentialVerificationStatus.Pending,
      },
    });
    if (existingPending) {
      throw new ConflictException(
        'A pending DID Web credential already exists for this user.',
      );
    }

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
      where: { credentialType: CredentialType.DidWeb, userId: user.id,credentialStatus: CredentialVerificationStatus.Pending, },
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
    end.setFullYear(end.getFullYear() + 3);

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
        id: resolveDidKey(user),
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
    result.proof = { type: 'JwtProof2020', jwt: jws };
    return result;
  }

  // ─── Membership Credential flow ─────────────────────────────────────────────

  async createPendingMembershipCredential(
    createMemberCredentialDto: CreateMemberCredentialDto,
    user: User,
    issuerId: number,
  ): Promise<Credential> {
    const existing = await this.credentialsRepository.findOne({
      where: {
        credentialType: CredentialType.Member,
        issuerId,
        userId: user.id,
        credentialStatus: CredentialVerificationStatus.Pending,
      },
    });

    if (existing) {
      throw new ConflictException(
        'A pending Membership credential request already exists for this issuer. Wait for it to be approved or rejected before submitting a new one.',
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

    return this.credentialsRepository.save(credential, { reload: true });
  }

  async initiateMembershipCredentialAcceptance(
    issuer: User,
    credentialId: number,
  ) {
    if (!issuer.externalCertPem) {
      throw new ConflictException(
        'Issuer must complete certificate challenge before accepting Membership credentials.',
      );
    }

    const pending = await this.credentialsRepository.findOne({
      where: {
        credentialType: CredentialType.Member,
        issuerId: issuer.id,
        id: credentialId,
        credentialStatus: CredentialVerificationStatus.Pending,
      },
      relations: ['user'],
    });

    if (!pending) {
      throw new ConflictException(
        'Pending Membership credential not found for this issuer.',
      );
    }

    const subjectDidKey = this.extractKeypairSnapshotDidKey(pending);

    const { credentialObject } = await generateMembershipCredentialObjectAndJWS(
      {
        value: pending.value,
        did: subjectDidKey ?? pending.user.didKey,
      },
      pending.user,
      issuer,
      subjectDidKey,
    );

    const signingInput = this.buildSigningInput(credentialObject, issuer.externalCertPem);
    const challenge = { signingInput, credentialObject, initiatedAt: new Date().toISOString() };

    pending.credentialObject = { ...(pending.credentialObject || {}), __acceptanceChallenge: challenge };
    await this.credentialsRepository.save(pending, { reload: true });

    const supportingCredential = await this.findMembershipSupportingCredential(pending.userId);

    return {
      challenge,
      commands: [
        `SIG=$(printf %s "${signingInput}" | openssl dgst -sha256 -sign your_private_key.pem -binary | openssl base64 -A | tr -d '\n') && echo "Signature length: ${"${#SIG}"}" && echo "$SIG" && echo "$SIG" | pbcopy`,
      ],
      supportingCredential,
    };
  }

  async verifyMembershipCredentialAcceptance(
    issuer: User,
    credentialId: number,
    signatureBase64: string,
  ): Promise<Credential> {
    if (!issuer.externalCertPem) {
      throw new ConflictException(
        'Issuer must complete certificate challenge before accepting Membership credentials.',
      );
    }

    const pending = await this.credentialsRepository.findOne({
      where: {
        credentialType: CredentialType.Member,
        issuerId: issuer.id,
        id: credentialId,
        credentialStatus: CredentialVerificationStatus.Pending,
      },
      relations: ['user'],
    });

    if (!pending) {
      throw new ConflictException('Pending Membership credential not found.');
    }

    return this.executeSignatureVerification(pending, issuer, signatureBase64);
  }

  private async findMembershipSupportingCredential(
    userId: number,
  ): Promise<{ credentialObject: any; proof: { type: string; jwt: string } } | undefined> {
    const found = await this.credentialsRepository.findOne({
      where: {
        userId,
        credentialType: CredentialType.EMail,
        credentialStatus: CredentialVerificationStatus.Success,
      },
      order: { createdAt: 'DESC' },
    });

    if (!found) return undefined;

    const credentialObject = { ...found.credentialObject };
    delete credentialObject.__keypairSnapshot;
    delete credentialObject.__acceptanceChallenge;

    return { credentialObject, proof: { type: 'JwtProof2020', jwt: found.token } };
  }

  // ─── Data Supplier Credential flow ───────────────────────────────────────────

  async createPendingDataSupplierCredential(
    createMemberCredentialDto: CreateMemberCredentialDto,
    user: User,
    issuerId: number,
    keypairSnapshot: { derivedDidKey: string; publicKeyPem: string },
  ): Promise<Credential> {
    const existing = await this.credentialsRepository.findOne({
      where: {
        credentialType: CredentialType.DataSupplier,
        issuerId,
        userId: user.id,
        credentialStatus: CredentialVerificationStatus.Pending,
      },
    });

    if (existing) {
      throw new ConflictException(
        'A pending Data Supplier credential request already exists for this issuer. Wait for it to be approved or rejected before submitting a new one.',
      );
    }

    const credential = this.credentialsRepository.create({
      email: createMemberCredentialDto.value,
      value: createMemberCredentialDto.value,
      issuerId,
      credentialType: CredentialType.DataSupplier,
      credentialStatus: CredentialVerificationStatus.Pending,
      credentialObject: {
        __keypairSnapshot: {
          derivedDidKey: keypairSnapshot.derivedDidKey,
          publicKeyPem: keypairSnapshot.publicKeyPem,
          capturedAt: new Date().toISOString(),
        },
      },
      token: '',
      user,
    });

    const savedCredential = await this.credentialsRepository.save(credential, { reload: true });

    const emailCredential = await this.credentialsRepository.findOne({
      where: {
        userId: user.id,
        credentialType: CredentialType.EMail,
        credentialStatus: CredentialVerificationStatus.Success,
      },
      order: { createdAt: 'DESC' },
    });
    const userEmail = emailCredential?.email ?? '';

    const { credentialObject: ekvcObject, jws: ekvcJws } =
      await generateExternalKeypairVerificationCredentialObjectAndJWS(
        user,
        keypairSnapshot.derivedDidKey,
        userEmail,
      );
    const ekvcCredential = this.credentialsRepository.create({
      email: keypairSnapshot.derivedDidKey,
      value: keypairSnapshot.derivedDidKey,
      credentialType: CredentialType.ExternalKeypairVerification,
      credentialStatus: CredentialVerificationStatus.Success,
      credentialObject: ekvcObject,
      token: ekvcJws,
      user,
    });
    await this.credentialsRepository.save(ekvcCredential);

    return savedCredential;
  }

  async initiateDataSupplierCredentialAcceptance(
    issuer: User,
    credentialId: number,
  ) {
    if (!issuer.externalCertPem) {
      throw new ConflictException(
        'Issuer must complete certificate challenge before accepting Data Supplier credentials.',
      );
    }

    const pending = await this.credentialsRepository.findOne({
      where: {
        credentialType: CredentialType.DataSupplier,
        issuerId: issuer.id,
        id: credentialId,
        credentialStatus: CredentialVerificationStatus.Pending,
      },
      relations: ['user'],
    });

    if (!pending) {
      throw new ConflictException(
        'Pending Data Supplier credential not found for this issuer.',
      );
    }

    const subjectDidKey = this.extractKeypairSnapshotDidKey(pending);

    const { credentialObject } = await generateDataSupplierCredentialObjectAndJWS(
      {
        value: pending.value,
        did: subjectDidKey ?? pending.user.didKey,
      },
      pending.user,
      issuer,
      subjectDidKey,
      pending.user.organizationName,
    );

    const signingInput = this.buildSigningInput(credentialObject, issuer.externalCertPem);
    const challenge = { signingInput, credentialObject, initiatedAt: new Date().toISOString() };

    pending.credentialObject = { ...(pending.credentialObject || {}), __acceptanceChallenge: challenge };
    await this.credentialsRepository.save(pending, { reload: true });

    const supportingCredential = await this.findDataSupplierSupportingCredential(pending.userId);

    return {
      challenge,
      commands: [
        `SIG=$(printf %s "${signingInput}" | openssl dgst -sha256 -sign your_private_key.pem -binary | openssl base64 -A | tr -d '\n') && echo "Signature length: ${"${#SIG}"}" && echo "$SIG" && echo "$SIG" | pbcopy`,
      ],
      supportingCredential,
    };
  }

  async verifyDataSupplierCredentialAcceptance(
    issuer: User,
    credentialId: number,
    signatureBase64: string,
  ): Promise<Credential> {
    if (!issuer.externalCertPem) {
      throw new ConflictException(
        'Issuer must complete certificate challenge before accepting Data Supplier credentials.',
      );
    }

    const pending = await this.credentialsRepository.findOne({
      where: {
        credentialType: CredentialType.DataSupplier,
        issuerId: issuer.id,
        id: credentialId,
        credentialStatus: CredentialVerificationStatus.Pending,
      },
      relations: ['user'],
    });

    if (!pending) {
      throw new ConflictException('Pending Data Supplier credential not found.');
    }

    return this.executeSignatureVerification(pending, issuer, signatureBase64);
  }

  private async findDataSupplierSupportingCredential(
    userId: number,
  ): Promise<{ credentialObject: any; proof: { type: string; jwt: string } } | undefined> {
    const found = await this.credentialsRepository.findOne({
      where: {
        userId,
        credentialType: CredentialType.ExternalKeypairVerification,
        credentialStatus: CredentialVerificationStatus.Success,
      },
      order: { createdAt: 'DESC' },
    });

    if (!found) return undefined;

    const credentialObject = { ...found.credentialObject };
    delete credentialObject.__keypairSnapshot;
    delete credentialObject.__acceptanceChallenge;

    return { credentialObject, proof: { type: 'JwtProof2020', jwt: found.token } };
  }

  // ─── Liccium Data Supplier Credential flow ───────────────────────────────────

  async createPendingLicciumDataSupplierCredential(
    createMemberCredentialDto: CreateMemberCredentialDto,
    user: User,
    issuerId: number,
    keypairSnapshot: { derivedDidKey: string; publicKeyPem: string },
  ): Promise<Credential> {
    const existing = await this.credentialsRepository.findOne({
      where: {
        credentialType: CredentialType.LicciumDataSupplier,
        issuerId,
        userId: user.id,
        credentialStatus: CredentialVerificationStatus.Pending,
      },
    });

    if (existing) {
      throw new ConflictException(
        'A pending Liccium Data Supplier credential request already exists for this issuer. Wait for it to be approved or rejected before submitting a new one.',
      );
    }

    const credential = this.credentialsRepository.create({
      email: createMemberCredentialDto.value,
      value: createMemberCredentialDto.value,
      issuerId,
      credentialType: CredentialType.LicciumDataSupplier,
      credentialStatus: CredentialVerificationStatus.Pending,
      credentialObject: {
        __keypairSnapshot: {
          derivedDidKey: keypairSnapshot.derivedDidKey,
          publicKeyPem: keypairSnapshot.publicKeyPem,
          capturedAt: new Date().toISOString(),
        },
      },
      token: '',
      user,
    });

    const savedCredential = await this.credentialsRepository.save(credential, { reload: true });

    const emailCredential = await this.credentialsRepository.findOne({
      where: {
        userId: user.id,
        credentialType: CredentialType.EMail,
        credentialStatus: CredentialVerificationStatus.Success,
      },
      order: { createdAt: 'DESC' },
    });
    const userEmail = emailCredential?.email ?? '';

    const { credentialObject: ekvcObject, jws: ekvcJws } =
      await generateExternalKeypairVerificationCredentialObjectAndJWS(
        user,
        keypairSnapshot.derivedDidKey,
        userEmail,
      );
    const ekvcCredential = this.credentialsRepository.create({
      email: keypairSnapshot.derivedDidKey,
      value: keypairSnapshot.derivedDidKey,
      credentialType: CredentialType.ExternalKeypairVerification,
      credentialStatus: CredentialVerificationStatus.Success,
      credentialObject: ekvcObject,
      token: ekvcJws,
      user,
    });
    await this.credentialsRepository.save(ekvcCredential);

    return savedCredential;
  }

  async initiateLicciumDataSupplierCredentialAcceptance(
    issuer: User,
    credentialId: number,
  ) {
    if (!issuer.externalCertPem) {
      throw new ConflictException(
        'Issuer must complete certificate challenge before accepting Liccium Data Supplier credentials.',
      );
    }

    const pending = await this.credentialsRepository.findOne({
      where: {
        credentialType: CredentialType.LicciumDataSupplier,
        issuerId: issuer.id,
        id: credentialId,
        credentialStatus: CredentialVerificationStatus.Pending,
      },
      relations: ['user'],
    });

    if (!pending) {
      throw new ConflictException(
        'Pending Liccium Data Supplier credential not found for this issuer.',
      );
    }

    const subjectDidKey = this.extractKeypairSnapshotDidKey(pending);

    const { credentialObject } = await generateLicciumDataSupplierCredentialObjectAndJWS(
      {
        value: pending.value,
        did: subjectDidKey ?? pending.user.didKey,
      },
      pending.user,
      issuer,
      subjectDidKey,
    );

    const signingInput = this.buildSigningInput(credentialObject, issuer.externalCertPem);
    const challenge = { signingInput, credentialObject, initiatedAt: new Date().toISOString() };

    pending.credentialObject = { ...(pending.credentialObject || {}), __acceptanceChallenge: challenge };
    await this.credentialsRepository.save(pending, { reload: true });

    const supportingCredential = await this.findDataSupplierSupportingCredential(pending.userId);

    return {
      challenge,
      commands: [
        `SIG=$(printf %s "${signingInput}" | openssl dgst -sha256 -sign your_private_key.pem -binary | openssl base64 -A | tr -d '\n') && echo "Signature length: ${"${#SIG}"}" && echo "$SIG" && echo "$SIG" | pbcopy`,
      ],
      supportingCredential,
    };
  }

  async verifyLicciumDataSupplierCredentialAcceptance(
    issuer: User,
    credentialId: number,
    signatureBase64: string,
  ): Promise<Credential> {
    if (!issuer.externalCertPem) {
      throw new ConflictException(
        'Issuer must complete certificate challenge before accepting Liccium Data Supplier credentials.',
      );
    }

    const pending = await this.credentialsRepository.findOne({
      where: {
        credentialType: CredentialType.LicciumDataSupplier,
        issuerId: issuer.id,
        id: credentialId,
        credentialStatus: CredentialVerificationStatus.Pending,
      },
      relations: ['user'],
    });

    if (!pending) {
      throw new ConflictException('Pending Liccium Data Supplier credential not found.');
    }

    return this.executeSignatureVerification(pending, issuer, signatureBase64);
  }

  // ─── Shared accept/verify utility ────────────────────────────────────────────

  async getPendingCredentialType(
    credentialId: number,
    issuerId: number,
  ): Promise<CredentialType | null> {
    const credential = await this.credentialsRepository.findOne({
      where: {
        id: credentialId,
        issuerId,
        credentialStatus: CredentialVerificationStatus.Pending,
      },
    });
    return credential?.credentialType ?? null;
  }

  private async executeSignatureVerification(
    pending: Credential,
    issuer: User,
    signatureBase64: string,
  ): Promise<Credential> {
    const challenge = (pending.credentialObject || {}).__acceptanceChallenge as
      | { signingInput: string; credentialObject: any }
      | undefined;

    if (!challenge?.signingInput || !challenge?.credentialObject) {
      throw new ConflictException('Acceptance challenge not initiated.');
    }

    const normalizedSignature = signatureBase64.replace(/\s/g, '');
    const signatureBuffer = Buffer.from(normalizedSignature, 'base64');
    if (!signatureBuffer.length) {
      throw new ConflictException('Signature is empty or invalid base64.');
    }

    const cert = new crypto.X509Certificate(issuer.externalCertPem);
    const signatureView = new Uint8Array(signatureBuffer);
    const isValid = crypto
      .createVerify('SHA256')
      .update(challenge.signingInput)
      .verify(cert.publicKey, signatureView);

    if (!isValid) {
      throw new ConflictException('Signature verification failed.');
    }

    const token = `${challenge.signingInput}.${this.toBase64Url(signatureBuffer)}`;

    pending.credentialStatus = CredentialVerificationStatus.Success;
    pending.credentialObject = challenge.credentialObject;
    pending.token = token;

    await this.credentialsRepository.save(pending, { reload: true });

    const result = pending.credentialObject;
    result.proof = { type: 'JwtProof2020', jwt: token };
    return result;
  }

  /**
   * If the pending credential row was created right after the creator
   * completed a single-use keypair challenge, the verified did:key was
   * snapshotted onto the credential's JSON column. We pull it out here so
   * every downstream issuance path uses the just-proven did:key as the
   * credentialSubject.id rather than the platform-default did:key. This is
   * what makes the keypair challenge actually bind to *this* credential.
   */
  private extractKeypairSnapshotDidKey(
    credential: Credential,
  ): string | undefined {
    const snapshot = (credential.credentialObject || {}).__keypairSnapshot as
      | { derivedDidKey?: string }
      | undefined;
    return snapshot?.derivedDidKey;
  }

  private buildSigningInput(payload: any, issuerCertPem: string): string {
    const certB64 = issuerCertPem
      .replace(/-----BEGIN CERTIFICATE-----/, '')
      .replace(/-----END CERTIFICATE-----/, '')
      .replace(/\s/g, '');
    const cert = new crypto.X509Certificate(issuerCertPem);
    const keyType = cert.publicKey.asymmetricKeyType;
    const alg = keyType === 'ec' ? 'ES256' : 'RS256';
    const header = {
      alg,
      x5c: [certB64],
      typ: 'JWT',
    };
    const encodedHeader = this.toBase64Url(Buffer.from(JSON.stringify(header)));
    const encodedPayload = this.toBase64Url(Buffer.from(JSON.stringify(payload)));
    return `${encodedHeader}.${encodedPayload}`;
  }

  private toBase64Url(input: Buffer): string {
    return input
      .toString('base64')
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=+$/g, '');
  }
}
