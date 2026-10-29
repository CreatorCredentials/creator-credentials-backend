import {
  ConflictException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import {
  DeleteResult,
  MoreThanOrEqual,
  Repository,
  SelectQueryBuilder,
} from 'typeorm';
import { CreateEmailCredentialDto } from './dto/create-email-credential.dto';
import { Credential } from './credential.entity';
import * as jose from 'jose';
import { ClerkRole, User } from 'src/users/user.entity';
import { v4 as uuidv4 } from 'uuid';
import { CreateWalletCredentialDto } from './dto/create-wallet-credential.dto';
import { CreateDomainCredentialDto } from './dto/create-domain-credential.dto';
import { CreateDidWebCredentialDto } from './dto/create-didweb-credential.dto';
import { CredentialType } from 'src/shared/typings/CredentialType';
import { CredentialVerificationStatus } from 'src/shared/typings/CredentialVerificationStatus';
import { CreateMemberCredentialDto } from './dto/create-member-credential.dto';
import {
  generateConnectCredentialObjectAndJWS,
  generateCreatorCredentialObjectAndJWS,
  generateDataSupplierCredentialObjectAndJWS,
  generateLicciumDataSupplierCredentialObjectAndJWS,
  generateDomainCredentialObjectAndJWS,
  generateEmailCredentialObjectAndJWS,
  generateExternalKeypairVerificationCredentialObjectAndJWS,
  generateMembershipCredentialObjectAndJWS,
  PLATFORM_DID,
  resolveDidKey,
} from './credentials.helpers';
import { CreateConnectCredentialDto } from './dto/create-connect-credential.dto';
import * as crypto from 'crypto';
import { normalizeEcdsaSignature } from './signature-encoding';
import { stripTransientFields } from './credentials.formatters';
import { EventEmitter2 } from '@nestjs/event-emitter';
import {
  CredentialRequestedEvent,
  CredentialRevokedEvent,
  NotificationEvent,
} from 'src/notifications/notification-events';
import { StatusListService } from 'src/status-list/status-list.service';
import { CredentialStatusEntry } from 'src/status-list/status-list.types';

const credentialsHost = 'liccium.com';
const POSTGRES_UNIQUE_VIOLATION = '23505';

/** Request types created together with an EKVC row (see createPending*DataSupplierCredential). */
const REQUEST_TYPES_WITH_KEYPAIR_VERIFICATION: CredentialType[] = [
  CredentialType.DataSupplier,
  CredentialType.LicciumDataSupplier,
];

@Injectable()
export class CredentialsService {
  constructor(
    @InjectRepository(Credential)
    private credentialsRepository: Repository<Credential>,
    private eventEmitter: EventEmitter2,
    private statusList: StatusListService,
  ) {}

  async getById(id: number, clerkId: string): Promise<Credential> {
    return this.credentialsRepository.findOne({
      where: { id, user: { clerkId } },
    });
  }

  /**
   * Credentials an issuer has issued (or that await it), with everything the
   * issued-credential shape renders per creator. One query, no per-row lookups.
   */
  async getAllIssuersMemberCredentialsWithCreators(
    issuerId: number,
    status: CredentialVerificationStatus = CredentialVerificationStatus.Success,
  ): Promise<Credential[]> {
    return this.issuedCredentialQuery()
      .where('credential.issuerId = :issuerId', { issuerId })
      .andWhere('credential.credentialStatus = :status', { status })
      .getMany();
  }

  /**
   * Issued credentials with only what the issued shape renders per creator:
   * the creator, their SUCCESS EMAIL credential and their connections.
   */
  private issuedCredentialQuery(): SelectQueryBuilder<Credential> {
    return this.credentialsRepository
      .createQueryBuilder('credential')
      .leftJoinAndSelect('credential.user', 'creator')
      .leftJoinAndSelect('creator.createdConnections', 'connection')
      .leftJoinAndSelect(
        'creator.credentials',
        'email',
        'email.credentialType = :emailType AND email.credentialStatus = :issued',
        {
          emailType: CredentialType.EMail,
          issued: CredentialVerificationStatus.Success,
        },
      );
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

  /**
   * Moves an issued (SUCCESS) credential of this issuer to REVOKED. The row
   * is kept so the creator sees why the credential is gone. Repeating the
   * call changes nothing; a PENDING request is rejected, not revoked.
   */
  async revokeIssuedCredential(
    credentialId: number,
    issuer: User,
    reason?: string,
  ): Promise<Credential> {
    const credential = await this.loadOwnedCredential(credentialId, issuer.id);
    return this.revoke(credential, issuer, reason);
  }

  /**
   * Platform-side revocation: an admin may revoke any issued credential, the
   * ownership rule does not apply. Same state rules as the issuer's revoke.
   */
  async revokeCredentialAsAdmin(
    credentialId: number,
    admin: User,
    reason?: string,
  ): Promise<Credential> {
    const credential = await this.loadCredentialWithParties(credentialId);
    return this.revoke(credential, admin, reason);
  }

  private async revoke(
    credential: Credential,
    revokedBy: User,
    reason?: string,
  ): Promise<Credential> {
    switch (credential.credentialStatus) {
      case CredentialVerificationStatus.Revoked:
        return credential;
      case CredentialVerificationStatus.Success:
        return this.markRevoked(credential, revokedBy, reason);
      case CredentialVerificationStatus.Pending:
        throw new ConflictException('Use reject for pending credentials');
      default:
        throw new ConflictException(
          `A credential in status ${credential.credentialStatus} cannot be revoked.`,
        );
    }
  }

  /**
   * Removes a PENDING request of this issuer together with the keypair
   * verification created for it. Issued credentials are revoked, not removed.
   */
  async rejectPendingCredential(
    credentialId: number,
    issuer: User,
  ): Promise<void> {
    const credential = await this.loadOwnedCredential(credentialId, issuer.id);

    if (credential.credentialStatus !== CredentialVerificationStatus.Pending) {
      throw new ConflictException('Use revoke for issued credentials');
    }

    await this.removeKeypairVerificationOfRequest(credential);
    await this.credentialsRepository.delete({ id: credential.id });
  }

  /**
   * A credential belongs to the issuer it was requested from. A foreign or
   * unknown id answers 404 on purpose: the response must not confirm that
   * the id exists.
   */
  private async loadOwnedCredential(
    credentialId: number,
    issuerId: number,
  ): Promise<Credential> {
    const credential = await this.issuedCredentialQuery()
      .leftJoinAndSelect('credential.issuer', 'issuer')
      .where(
        'credential.id = :credentialId AND credential.issuerId = :issuerId',
        {
          credentialId,
          issuerId,
        },
      )
      .getOne();

    if (!credential) {
      throw new NotFoundException('Credential not found.');
    }

    return credential;
  }

  /** Any credential by id with creator, issuer and revoker loaded (admin path). */
  private async loadCredentialWithParties(
    credentialId: number,
  ): Promise<Credential> {
    const credential = await this.issuedCredentialQuery()
      .leftJoinAndSelect('credential.issuer', 'issuer')
      .leftJoinAndSelect('credential.revokedBy', 'revokedBy')
      .where('credential.id = :credentialId', { credentialId })
      .getOne();

    if (!credential) {
      throw new NotFoundException('Credential not found.');
    }

    return credential;
  }

  private async markRevoked(
    credential: Credential,
    revokedBy: User,
    reason?: string,
  ): Promise<Credential> {
    credential.credentialStatus = CredentialVerificationStatus.Revoked;
    credential.revokedAt = new Date();
    credential.revokedReason = reason?.trim() || null;
    credential.revokedBy = revokedBy;
    credential.revokedByUserId = revokedBy.id;
    const revoked = await this.credentialsRepository.save(credential);
    this.statusList.invalidate();
    this.emitCredentialRevoked(revoked, revokedBy.clerkRole);
    return revoked;
  }

  /**
   * A data-supplier request is created together with an EKVC row that attests
   * the did:key snapshotted on the request. Rejecting the request removes that
   * EKVC so the creator can run a new keypair challenge and request again.
   * The link is the did:key, which the EKVC stores in `value`; only rows
   * created with or after the request are removed, so an earlier issued
   * credential that reused the same key keeps its EKVC. The EKVC goes first:
   * if that delete fails the request stays and the rejection can be retried.
   */
  private async removeKeypairVerificationOfRequest(
    request: Credential,
  ): Promise<void> {
    if (
      !REQUEST_TYPES_WITH_KEYPAIR_VERIFICATION.includes(request.credentialType)
    ) {
      return;
    }

    const derivedDidKey = this.extractKeypairSnapshotDidKey(request);
    if (!derivedDidKey) {
      return;
    }

    await this.credentialsRepository.delete({
      userId: request.userId,
      credentialType: CredentialType.ExternalKeypairVerification,
      value: derivedDidKey,
      createdAt: MoreThanOrEqual(request.createdAt),
    });
  }

  /**
   * Platform-issued attestation that the creator's Liccium account is
   * linked. One SUCCESS row per user: an existing row is returned as is, so
   * the callers (Liccium connect and export) stay idempotent.
   */
  async ensureCreatorCredential(user: User): Promise<Credential> {
    const existing = await this.findCreatorCredential(user);
    if (existing) {
      return existing;
    }

    const { index, credentialStatus } = await this.statusList.reserveEntry();
    const { credentialObject, jws } =
      await generateCreatorCredentialObjectAndJWS(
        user,
        credentialsHost,
        credentialStatus,
      );
    const credential = this.credentialsRepository.create({
      email: credentialsHost,
      value: credentialsHost,
      credentialType: CredentialType.Creator,
      credentialStatus: CredentialVerificationStatus.Success,
      credentialObject,
      token: jws,
      statusListIndex: index,
      user,
    });

    try {
      return await this.credentialsRepository.save(credential, {
        reload: true,
      });
    } catch (error) {
      // Unique violation: a concurrent request issued the row first.
      if (error?.code === POSTGRES_UNIQUE_VIOLATION) {
        return this.findCreatorCredential(user);
      }
      throw error;
    }
  }

  private findCreatorCredential(user: User): Promise<Credential | null> {
    return this.credentialsRepository.findOne({
      where: {
        userId: user.id,
        credentialType: CredentialType.Creator,
        credentialStatus: CredentialVerificationStatus.Success,
      },
    });
  }

  private emitCredentialRequested(request: Credential, creator: User): void {
    const payload: CredentialRequestedEvent = {
      credentialId: request.id,
      issuerId: request.issuerId,
      creatorId: creator.id,
      credentialType: request.credentialType,
    };
    this.eventEmitter.emit(NotificationEvent.CredentialRequested, payload);
  }

  private emitCredentialRevoked(
    credential: Credential,
    revokedByRole: ClerkRole,
  ): void {
    const payload: CredentialRevokedEvent = {
      credentialId: credential.id,
      issuerId: credential.issuerId,
      creatorId: credential.userId,
      credentialType: credential.credentialType,
      reason: credential.revokedReason ?? null,
      revokedByRole,
    };
    this.eventEmitter.emit(NotificationEvent.CredentialRevoked, payload);
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

    const { index, credentialStatus } = await this.statusList.reserveEntry();
    const credentialObject = {
      '@context': ['https://www.w3.org/ns/credentials/v2'],
      id: `urn:uuid:${uuidv4()}`,
      type: [
        'VerifiableCredential',
        'VerifiableAttestation',
        'VerifiableWallet',
      ],
      issuer: PLATFORM_DID,
      validFrom: now.toISOString(),
      validUntil: end.toISOString(),
      credentialSubject: {
        id: resolveDidKey(user),
        walletAddress: createWalletCredentialDto.publicAddress,
      },
      credentialStatus,
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
      statusListIndex: index,
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

    const { index, credentialStatus } = await this.statusList.reserveEntry();
    const { credentialObject, jws } = await generateEmailCredentialObjectAndJWS(
      createEmailCredentialDto,
      user,
      credentialStatus,
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
      statusListIndex: index,
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

    const { index, credentialStatus } = await this.statusList.reserveEntry();
    const { credentialObject, jws } =
      await generateConnectCredentialObjectAndJWS(
        createConnectCredentialDto,
        credentialStatus,
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
      email: createConnectCredentialDto.licciumDidKey,
      credentialType: CredentialType.Connect,
      credentialObject,
      credentialStatus: CredentialVerificationStatus.Success,
      token: jws,
      statusListIndex: index,
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

    const { index, credentialStatus } = await this.statusList.reserveEntry();
    const { credentialObject, jws } =
      await generateDomainCredentialObjectAndJWS(
        createDomainCredentialDto,
        user,
        credentialStatus,
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
      statusListIndex: index,
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
      where: {
        credentialType: CredentialType.DidWeb,
        userId: user.id,
        credentialStatus: CredentialVerificationStatus.Pending,
      },
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

    const { index, credentialStatus } = await this.statusList.reserveEntry();
    const credentialObject = {
      '@context': ['https://www.w3.org/ns/credentials/v2'],
      id: `urn:uuid:${uuidv4()}`,
      type: [
        'VerifiableCredential',
        'VerifiableAttestation',
        'VerifiableDidWeb',
      ],
      issuer: PLATFORM_DID,
      validFrom: now.toISOString(),
      validUntil: end.toISOString(),
      credentialSubject: {
        id: resolveDidKey(user),
        didWeb: createDidWebCredentialDto.didWeb,
      },
      credentialStatus,
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
      statusListIndex: index,
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

    const savedCredential = await this.credentialsRepository.save(credential, {
      reload: true,
    });
    this.emitCredentialRequested(savedCredential, user);

    return savedCredential;
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
    const credentialStatus = await this.reserveStatusListEntryFor(pending);

    const { credentialObject } = await generateMembershipCredentialObjectAndJWS(
      {
        value: pending.value,
        did: subjectDidKey ?? pending.user.didKey,
      },
      pending.user,
      issuer,
      subjectDidKey,
      credentialStatus,
    );

    const signingInput = this.buildSigningInput(
      credentialObject,
      issuer.externalCertPem,
    );
    const challenge = {
      signingInput,
      credentialObject,
      initiatedAt: new Date().toISOString(),
    };

    pending.credentialObject = {
      ...(pending.credentialObject || {}),
      __acceptanceChallenge: challenge,
    };
    await this.credentialsRepository.save(pending, { reload: true });

    const supportingCredential = await this.findMembershipSupportingCredential(
      pending.userId,
    );

    return {
      challenge,
      commands: [
        `SIG=$(printf %s "${signingInput}" | openssl dgst -sha256 -sign your_private_key.pem -binary | openssl base64 -A | tr -d '\n') && echo "Signature length: ${'${#SIG}'}" && echo "$SIG" && echo "$SIG" | pbcopy`,
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
  ): Promise<
    { credentialObject: any; proof: { type: string; jwt: string } } | undefined
  > {
    const found = await this.credentialsRepository.findOne({
      where: {
        userId,
        credentialType: CredentialType.EMail,
        credentialStatus: CredentialVerificationStatus.Success,
      },
      order: { createdAt: 'DESC' },
    });

    if (!found) return undefined;

    const credentialObject = stripTransientFields(found.credentialObject);

    return {
      credentialObject,
      proof: { type: 'JwtProof2020', jwt: found.token },
    };
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

    const savedCredential = await this.credentialsRepository.save(credential, {
      reload: true,
    });

    const emailCredential = await this.credentialsRepository.findOne({
      where: {
        userId: user.id,
        credentialType: CredentialType.EMail,
        credentialStatus: CredentialVerificationStatus.Success,
      },
      order: { createdAt: 'DESC' },
    });
    const userEmail = emailCredential?.email ?? '';

    const ekvcEntry = await this.statusList.reserveEntry();
    const { credentialObject: ekvcObject, jws: ekvcJws } =
      await generateExternalKeypairVerificationCredentialObjectAndJWS(
        user,
        keypairSnapshot.derivedDidKey,
        userEmail,
        user.organizationName,
        ekvcEntry.credentialStatus,
      );
    const ekvcCredential = this.credentialsRepository.create({
      email: keypairSnapshot.derivedDidKey,
      value: keypairSnapshot.derivedDidKey,
      credentialType: CredentialType.ExternalKeypairVerification,
      credentialStatus: CredentialVerificationStatus.Success,
      credentialObject: ekvcObject,
      token: ekvcJws,
      statusListIndex: ekvcEntry.index,
      user,
    });
    await this.credentialsRepository.save(ekvcCredential);
    this.emitCredentialRequested(savedCredential, user);

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
    const credentialStatus = await this.reserveStatusListEntryFor(pending);

    const { credentialObject } =
      await generateDataSupplierCredentialObjectAndJWS(
        {
          value: pending.value,
          did: subjectDidKey ?? pending.user.didKey,
        },
        pending.user,
        issuer,
        subjectDidKey,
        pending.user.organizationName,
        credentialStatus,
      );

    const signingInput = this.buildSigningInput(
      credentialObject,
      issuer.externalCertPem,
    );
    const challenge = {
      signingInput,
      credentialObject,
      initiatedAt: new Date().toISOString(),
    };

    pending.credentialObject = {
      ...(pending.credentialObject || {}),
      __acceptanceChallenge: challenge,
    };
    await this.credentialsRepository.save(pending, { reload: true });

    const supportingCredential =
      await this.findDataSupplierSupportingCredential(pending.userId);

    return {
      challenge,
      commands: [
        `SIG=$(printf %s "${signingInput}" | openssl dgst -sha256 -sign your_private_key.pem -binary | openssl base64 -A | tr -d '\n') && echo "Signature length: ${'${#SIG}'}" && echo "$SIG" && echo "$SIG" | pbcopy`,
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
      throw new ConflictException(
        'Pending Data Supplier credential not found.',
      );
    }

    return this.executeSignatureVerification(pending, issuer, signatureBase64);
  }

  private async findDataSupplierSupportingCredential(
    userId: number,
  ): Promise<
    { credentialObject: any; proof: { type: string; jwt: string } } | undefined
  > {
    const found = await this.credentialsRepository.findOne({
      where: {
        userId,
        credentialType: CredentialType.ExternalKeypairVerification,
        credentialStatus: CredentialVerificationStatus.Success,
      },
      order: { createdAt: 'DESC' },
    });

    if (!found) return undefined;

    const credentialObject = stripTransientFields(found.credentialObject);

    return {
      credentialObject,
      proof: { type: 'JwtProof2020', jwt: found.token },
    };
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

    const savedCredential = await this.credentialsRepository.save(credential, {
      reload: true,
    });

    const emailCredential = await this.credentialsRepository.findOne({
      where: {
        userId: user.id,
        credentialType: CredentialType.EMail,
        credentialStatus: CredentialVerificationStatus.Success,
      },
      order: { createdAt: 'DESC' },
    });
    const userEmail = emailCredential?.email ?? '';

    const ekvcEntry = await this.statusList.reserveEntry();
    const { credentialObject: ekvcObject, jws: ekvcJws } =
      await generateExternalKeypairVerificationCredentialObjectAndJWS(
        user,
        keypairSnapshot.derivedDidKey,
        userEmail,
        undefined,
        ekvcEntry.credentialStatus,
      );
    const ekvcCredential = this.credentialsRepository.create({
      email: keypairSnapshot.derivedDidKey,
      value: keypairSnapshot.derivedDidKey,
      credentialType: CredentialType.ExternalKeypairVerification,
      credentialStatus: CredentialVerificationStatus.Success,
      credentialObject: ekvcObject,
      token: ekvcJws,
      statusListIndex: ekvcEntry.index,
      user,
    });
    await this.credentialsRepository.save(ekvcCredential);
    this.emitCredentialRequested(savedCredential, user);

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
    const credentialStatus = await this.reserveStatusListEntryFor(pending);

    const { credentialObject } =
      await generateLicciumDataSupplierCredentialObjectAndJWS(
        {
          value: pending.value,
          did: subjectDidKey ?? pending.user.didKey,
        },
        pending.user,
        issuer,
        subjectDidKey,
        credentialStatus,
      );

    const signingInput = this.buildSigningInput(
      credentialObject,
      issuer.externalCertPem,
    );
    const challenge = {
      signingInput,
      credentialObject,
      initiatedAt: new Date().toISOString(),
    };

    pending.credentialObject = {
      ...(pending.credentialObject || {}),
      __acceptanceChallenge: challenge,
    };
    await this.credentialsRepository.save(pending, { reload: true });

    const supportingCredential =
      await this.findDataSupplierSupportingCredential(pending.userId);

    return {
      challenge,
      commands: [
        `SIG=$(printf %s "${signingInput}" | openssl dgst -sha256 -sign your_private_key.pem -binary | openssl base64 -A | tr -d '\n') && echo "Signature length: ${'${#SIG}'}" && echo "$SIG" && echo "$SIG" | pbcopy`,
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
      throw new ConflictException(
        'Pending Liccium Data Supplier credential not found.',
      );
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
    const storedSignature = this.verifySignatureOrThrow(
      cert.publicKey,
      challenge.signingInput,
      signatureBuffer,
    );

    const token = `${challenge.signingInput}.${this.toBase64Url(
      storedSignature,
    )}`;

    pending.credentialStatus = CredentialVerificationStatus.Success;
    pending.credentialObject = challenge.credentialObject;
    pending.token = token;

    await this.credentialsRepository.save(pending, { reload: true });

    const result = pending.credentialObject;
    result.proof = { type: 'JwtProof2020', jwt: token };
    return result;
  }

  /**
   * Verifies the issuer's signature over the signing input and returns it in
   * the encoding the JWS token stores. ES256 (EC certificate): the DER form
   * `openssl dgst -sign` emits is accepted and converted to raw r||s so
   * standard JOSE verifiers accept the token; tokens stored before this
   * conversion keep their DER signature. RS256: the PKCS#1 signature as is.
   */
  private verifySignatureOrThrow(
    publicKey: crypto.KeyObject,
    signingInput: string,
    signature: Buffer,
  ): Buffer {
    return publicKey.asymmetricKeyType === 'ec'
      ? this.verifyEcdsaSignature(publicKey, signingInput, signature)
      : this.verifyRsaSignature(publicKey, signingInput, signature);
  }

  private verifyEcdsaSignature(
    publicKey: crypto.KeyObject,
    signingInput: string,
    signature: Buffer,
  ): Buffer {
    const rawSignature = this.toRawEcdsaSignature(signature);
    const isValid = crypto.verify(
      'sha256',
      Buffer.from(signingInput),
      { key: publicKey, dsaEncoding: 'ieee-p1363' },
      rawSignature,
    );

    if (!isValid) {
      throw new ConflictException('Signature verification failed.');
    }

    return rawSignature;
  }

  private verifyRsaSignature(
    publicKey: crypto.KeyObject,
    signingInput: string,
    signature: Buffer,
  ): Buffer {
    const isValid = crypto
      .createVerify('SHA256')
      .update(signingInput)
      .verify(publicKey, signature);

    if (!isValid) {
      throw new ConflictException('Signature verification failed.');
    }

    return signature;
  }

  private toRawEcdsaSignature(signature: Buffer): Buffer {
    try {
      return normalizeEcdsaSignature(signature);
    } catch (error) {
      throw new ConflictException(
        `Signature is not a valid ECDSA signature: ${error.message}`,
      );
    }
  }

  /**
   * The status-list entry an issuer-issued credential is signed with. The
   * index is reserved when the acceptance is initiated and stored on the
   * pending row, so re-initiating the challenge reuses it instead of
   * consuming another entry.
   */
  private async reserveStatusListEntryFor(
    pending: Credential,
  ): Promise<CredentialStatusEntry> {
    if (pending.statusListIndex == null) {
      pending.statusListIndex = await this.statusList.allocateIndex();
    }
    return this.statusList.entryFor(pending.statusListIndex);
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
    const encodedPayload = this.toBase64Url(
      Buffer.from(JSON.stringify(payload)),
    );
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
