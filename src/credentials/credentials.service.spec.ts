import { Test, TestingModule } from '@nestjs/testing';
import { getRepositoryToken } from '@nestjs/typeorm';
import { ConflictException, NotFoundException } from '@nestjs/common';
import { MoreThanOrEqual } from 'typeorm';
import { EventEmitter2 } from '@nestjs/event-emitter';
import { CredentialsService } from './credentials.service';
import { Credential } from './credential.entity';
import {
  formatCreatorCredential,
  formatIssuedCredential,
  formatMemberCredential,
  stripTransientFields,
} from './credentials.formatters';
import { generateCreatorCredentialObjectAndJWS } from './credentials.helpers';
import { NotificationEvent } from 'src/notifications/notification-events';
import { ClerkRole, User } from 'src/users/user.entity';
import {
  Connection,
  ConnectionStatus,
} from 'src/connections/connection.entity';
import { CredentialType } from 'src/shared/typings/CredentialType';
import { CredentialVerificationStatus } from 'src/shared/typings/CredentialVerificationStatus';

jest.mock('./credentials.helpers', () => ({
  ...jest.requireActual('./credentials.helpers'),
  generateCreatorCredentialObjectAndJWS: jest.fn(),
}));

const ISSUER_ID = 10;
const OTHER_ISSUER_ID = 11;
const CREATOR_ID = 20;
const EXTERNAL_DID_KEY = 'did:key:zExternal';
const PLATFORM_HOST = 'liccium.com';

function buildUser(overrides: Partial<User>): User {
  return Object.assign(new User(), {
    credentials: [],
    createdConnections: [],
    ...overrides,
  });
}

function buildConnection(overrides: Partial<Connection>): Connection {
  return Object.assign(new Connection(), {
    issuerId: ISSUER_ID,
    creatorId: CREATOR_ID,
    ...overrides,
  });
}

const issuer = buildUser({
  id: ISSUER_ID,
  clerkRole: ClerkRole.Issuer,
  name: 'Issuer Inc',
});
const otherIssuer = buildUser({
  id: OTHER_ISSUER_ID,
  clerkRole: ClerkRole.Issuer,
  name: 'Other Inc',
});
const creator = buildUser({
  id: CREATOR_ID,
  clerkRole: ClerkRole.Creator,
  name: 'Alice',
  didKey: 'did:key:zAlice',
});

function buildCredential(overrides: Partial<Credential>): Credential {
  return Object.assign(new Credential(), {
    id: 1,
    issuerId: ISSUER_ID,
    issuer,
    userId: CREATOR_ID,
    user: creator,
    credentialType: CredentialType.Member,
    credentialStatus: CredentialVerificationStatus.Success,
    credentialObject: { id: 'urn:uuid:credential' },
    token: 'header.payload.signature',
    email: 'did:web:issuer.example',
    value: 'did:web:issuer.example',
    createdAt: new Date('2026-01-01T00:00:00.000Z'),
    updatedAt: new Date('2026-01-02T00:00:00.000Z'),
    ...overrides,
  });
}

function buildPendingDataSupplierRequest(): Credential {
  return buildCredential({
    credentialType: CredentialType.DataSupplier,
    credentialStatus: CredentialVerificationStatus.Pending,
    credentialObject: {
      __keypairSnapshot: {
        derivedDidKey: EXTERNAL_DID_KEY,
        publicKeyPem: 'pem',
        capturedAt: '2026-01-01T00:00:00.000Z',
      },
    },
  });
}

describe('CredentialsService', () => {
  const repository = {
    find: jest.fn(),
    findOne: jest.fn(),
    create: jest.fn(),
    save: jest.fn(),
    delete: jest.fn(),
    createQueryBuilder: jest.fn(),
  };
  const queryBuilder = {
    leftJoinAndSelect: jest.fn(),
    where: jest.fn(),
    andWhere: jest.fn(),
    getMany: jest.fn(),
    getOne: jest.fn(),
  };
  const eventEmitter = { emit: jest.fn() };
  let service: CredentialsService;

  beforeEach(async () => {
    jest.resetAllMocks();
    repository.createQueryBuilder.mockReturnValue(queryBuilder);
    queryBuilder.leftJoinAndSelect.mockReturnValue(queryBuilder);
    queryBuilder.where.mockReturnValue(queryBuilder);
    queryBuilder.andWhere.mockReturnValue(queryBuilder);
    repository.create.mockImplementation((fields: Partial<Credential>) =>
      Object.assign(new Credential(), fields),
    );
    repository.save.mockImplementation(
      async (credential: Credential) => credential,
    );

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        CredentialsService,
        { provide: getRepositoryToken(Credential), useValue: repository },
        { provide: EventEmitter2, useValue: eventEmitter },
      ],
    }).compile();

    service = module.get(CredentialsService);
  });

  /** The owned-credential query joins issuer, creator, connections and only the SUCCESS EMAIL row. */
  function expectOwnedCredentialQuery(credentialId: number) {
    expectIssuedCredentialJoins();
    expect(queryBuilder.leftJoinAndSelect).toHaveBeenCalledWith(
      'credential.issuer',
      'issuer',
    );
    expect(queryBuilder.where).toHaveBeenCalledWith(
      'credential.id = :credentialId AND credential.issuerId = :issuerId',
      { credentialId, issuerId: ISSUER_ID },
    );
  }

  function expectIssuedCredentialJoins() {
    expect(queryBuilder.leftJoinAndSelect).toHaveBeenCalledWith(
      'credential.user',
      'creator',
    );
    expect(queryBuilder.leftJoinAndSelect).toHaveBeenCalledWith(
      'creator.createdConnections',
      'connection',
    );
    expect(queryBuilder.leftJoinAndSelect).toHaveBeenCalledWith(
      'creator.credentials',
      'email',
      'email.credentialType = :emailType AND email.credentialStatus = :issued',
      {
        emailType: CredentialType.EMail,
        issued: CredentialVerificationStatus.Success,
      },
    );
  }

  describe('revokeIssuedCredential', () => {
    it('moves an issued credential of the issuer to REVOKED with timestamp and reason', async () => {
      queryBuilder.getOne.mockResolvedValue(buildCredential({}));
      const before = Date.now();

      const revoked = await service.revokeIssuedCredential(
        1,
        issuer,
        'Membership ended',
      );

      expect(revoked.credentialStatus).toBe(
        CredentialVerificationStatus.Revoked,
      );
      expect(revoked.revokedAt.getTime()).toBeGreaterThanOrEqual(before);
      expect(revoked.revokedReason).toBe('Membership ended');
      expect(repository.save).toHaveBeenCalledWith(revoked);
    });

    it('emits credential.revoked after the row is saved', async () => {
      queryBuilder.getOne.mockResolvedValue(buildCredential({}));

      await service.revokeIssuedCredential(1, issuer, 'Membership ended');

      expect(eventEmitter.emit).toHaveBeenCalledTimes(1);
      expect(eventEmitter.emit).toHaveBeenCalledWith(
        NotificationEvent.CredentialRevoked,
        {
          credentialId: 1,
          issuerId: ISSUER_ID,
          creatorId: CREATOR_ID,
          credentialType: CredentialType.Member,
          reason: 'Membership ended',
        },
      );
    });

    it('loads the credential scoped to the caller with issuer and user', async () => {
      queryBuilder.getOne.mockResolvedValue(buildCredential({}));

      const revoked = await service.revokeIssuedCredential(1, issuer);

      expectOwnedCredentialQuery(1);
      expect(revoked.issuer).toBe(issuer);
      expect(revoked.user).toBe(creator);
      expect(revoked.revokedReason).toBeNull();
    });

    it('returns a credential the issued shape can render with connection and e-mail', async () => {
      const connectedCreator = buildUser({
        id: CREATOR_ID,
        clerkRole: ClerkRole.Creator,
        name: 'Alice',
        didKey: 'did:key:zAlice',
        credentials: [
          buildCredential({
            id: 3,
            credentialType: CredentialType.EMail,
            email: 'alice@example.org',
          }),
        ],
        createdConnections: [
          buildConnection({ id: 2, status: ConnectionStatus.Accepted }),
        ],
      });
      queryBuilder.getOne.mockResolvedValue(
        buildCredential({ user: connectedCreator }),
      );

      const formatted = formatIssuedCredential(
        await service.revokeIssuedCredential(1, issuer, 'Membership ended'),
      );

      expect(formatted).toMatchObject({
        status: CredentialVerificationStatus.Revoked,
        revokedReason: 'Membership ended',
        connectionStatus: ConnectionStatus.Accepted,
        creator: { id: CREATOR_ID, email: 'alice@example.org' },
      });
    });

    it('answers 404 for a credential of another issuer and saves nothing', async () => {
      queryBuilder.getOne.mockResolvedValue(null);

      await expect(
        service.revokeIssuedCredential(1, otherIssuer),
      ).rejects.toBeInstanceOf(NotFoundException);

      expect(repository.save).not.toHaveBeenCalled();
    });

    it('answers 409 for a pending request', async () => {
      queryBuilder.getOne.mockResolvedValue(
        buildCredential({
          credentialStatus: CredentialVerificationStatus.Pending,
        }),
      );

      await expect(
        service.revokeIssuedCredential(1, issuer),
      ).rejects.toBeInstanceOf(ConflictException);

      expect(repository.save).not.toHaveBeenCalled();
    });

    it('returns an already revoked credential unchanged', async () => {
      const revokedAt = new Date('2026-02-01T00:00:00.000Z');
      queryBuilder.getOne.mockResolvedValue(
        buildCredential({
          credentialStatus: CredentialVerificationStatus.Revoked,
          revokedAt,
          revokedReason: 'first reason',
        }),
      );

      const result = await service.revokeIssuedCredential(
        1,
        issuer,
        'second reason',
      );

      expect(result.revokedAt).toBe(revokedAt);
      expect(result.revokedReason).toBe('first reason');
      expect(repository.save).not.toHaveBeenCalled();
      expect(eventEmitter.emit).not.toHaveBeenCalled();
    });
  });

  describe('rejectPendingCredential', () => {
    it('deletes a pending request of the issuer', async () => {
      queryBuilder.getOne.mockResolvedValue(
        buildCredential({
          credentialStatus: CredentialVerificationStatus.Pending,
        }),
      );

      await service.rejectPendingCredential(1, issuer);

      expectOwnedCredentialQuery(1);
      expect(repository.delete).toHaveBeenCalledTimes(1);
      expect(repository.delete).toHaveBeenCalledWith({ id: 1 });
    });

    it('answers 404 for a request of another issuer and deletes nothing', async () => {
      queryBuilder.getOne.mockResolvedValue(null);

      await expect(
        service.rejectPendingCredential(1, otherIssuer),
      ).rejects.toBeInstanceOf(NotFoundException);

      expect(repository.delete).not.toHaveBeenCalled();
    });

    it.each([
      CredentialVerificationStatus.Success,
      CredentialVerificationStatus.Revoked,
    ])('answers 409 for a credential in status %s', async (status) => {
      queryBuilder.getOne.mockResolvedValue(
        buildCredential({ credentialStatus: status }),
      );

      await expect(
        service.rejectPendingCredential(1, issuer),
      ).rejects.toBeInstanceOf(ConflictException);

      expect(repository.delete).not.toHaveBeenCalled();
    });

    it('removes the keypair verification created with a data-supplier request', async () => {
      const request = buildPendingDataSupplierRequest();
      queryBuilder.getOne.mockResolvedValue(request);

      await service.rejectPendingCredential(1, issuer);

      expect(repository.delete).toHaveBeenCalledTimes(2);
      expect(repository.delete).toHaveBeenNthCalledWith(1, {
        userId: CREATOR_ID,
        credentialType: CredentialType.ExternalKeypairVerification,
        value: EXTERNAL_DID_KEY,
        createdAt: MoreThanOrEqual(request.createdAt),
      });
      expect(repository.delete).toHaveBeenNthCalledWith(2, { id: 1 });
    });
  });

  describe('getAllIssuersMemberCredentialsWithCreators', () => {
    it('defaults to issued credentials and joins creator, connections and the verified e-mail only', async () => {
      queryBuilder.getMany.mockResolvedValue([]);

      await service.getAllIssuersMemberCredentialsWithCreators(ISSUER_ID);

      expectIssuedCredentialJoins();
      expect(queryBuilder.where).toHaveBeenCalledWith(
        'credential.issuerId = :issuerId',
        { issuerId: ISSUER_ID },
      );
      expect(queryBuilder.andWhere).toHaveBeenCalledWith(
        'credential.credentialStatus = :status',
        { status: CredentialVerificationStatus.Success },
      );
    });

    it('filters by the requested status, revoked included', async () => {
      queryBuilder.getMany.mockResolvedValue([]);

      await service.getAllIssuersMemberCredentialsWithCreators(
        ISSUER_ID,
        CredentialVerificationStatus.Revoked,
      );

      expect(queryBuilder.andWhere).toHaveBeenCalledWith(
        'credential.credentialStatus = :status',
        { status: CredentialVerificationStatus.Revoked },
      );
    });
  });

  describe('getCredentialsOfUserByType', () => {
    it('returns revoked rows alongside issued ones', async () => {
      const revoked = buildCredential({
        id: 2,
        credentialStatus: CredentialVerificationStatus.Revoked,
        revokedAt: new Date('2026-02-01T00:00:00.000Z'),
        revokedReason: 'Membership ended',
      });
      repository.find.mockResolvedValue([buildCredential({}), revoked]);

      const credentials = await service.getCredentialsOfUserByType(
        creator,
        CredentialType.Member,
      );

      expect(repository.find).toHaveBeenCalledWith({
        where: { userId: CREATOR_ID, credentialType: CredentialType.Member },
        relations: ['issuer'],
      });
      expect(credentials).toHaveLength(2);
      expect(formatMemberCredential(revoked)).toMatchObject({
        status: CredentialVerificationStatus.Revoked,
        revokedAt: revoked.revokedAt,
        revokedReason: 'Membership ended',
      });
    });
  });

  describe('createPendingMembershipCredential', () => {
    it('emits credential.requested once the request is stored', async () => {
      repository.findOne.mockResolvedValue(null);
      repository.save.mockImplementation(async (credential: Credential) =>
        Object.assign(credential, { id: 5 }),
      );

      const request = await service.createPendingMembershipCredential(
        { value: 'did:web:issuer.example', did: creator.didKey },
        creator,
        ISSUER_ID,
      );

      expect(request.credentialStatus).toBe(
        CredentialVerificationStatus.Pending,
      );
      expect(eventEmitter.emit).toHaveBeenCalledTimes(1);
      expect(eventEmitter.emit).toHaveBeenCalledWith(
        NotificationEvent.CredentialRequested,
        {
          credentialId: 5,
          issuerId: ISSUER_ID,
          creatorId: CREATOR_ID,
          credentialType: CredentialType.Member,
        },
      );
    });
  });

  describe('ensureCreatorCredential', () => {
    const builder = generateCreatorCredentialObjectAndJWS as jest.Mock;

    it('returns the existing Creator credential without issuing another', async () => {
      const existing = buildCredential({
        credentialType: CredentialType.Creator,
        issuerId: null,
        value: PLATFORM_HOST,
      });
      repository.findOne.mockResolvedValue(existing);

      await expect(service.ensureCreatorCredential(creator)).resolves.toBe(
        existing,
      );

      expect(repository.findOne).toHaveBeenCalledWith({
        where: {
          userId: CREATOR_ID,
          credentialType: CredentialType.Creator,
          credentialStatus: CredentialVerificationStatus.Success,
        },
      });
      expect(builder).not.toHaveBeenCalled();
      expect(repository.save).not.toHaveBeenCalled();
    });

    it('issues a SUCCESS Creator credential verified by the platform when none exists', async () => {
      repository.findOne.mockResolvedValue(null);
      builder.mockResolvedValue({
        credentialObject: { type: ['VerifiableCreator'] },
        jws: 'creator.jws',
      });

      const issued = await service.ensureCreatorCredential(creator);

      expect(builder).toHaveBeenCalledWith(creator, PLATFORM_HOST);
      expect(repository.save).toHaveBeenCalledTimes(1);
      expect(issued).toMatchObject({
        credentialType: CredentialType.Creator,
        credentialStatus: CredentialVerificationStatus.Success,
        value: PLATFORM_HOST,
        token: 'creator.jws',
        user: creator,
      });
    });

    it('returns the row a concurrent request issued first', async () => {
      const concurrentlyIssued = buildCredential({
        credentialType: CredentialType.Creator,
        issuerId: null,
        value: PLATFORM_HOST,
      });
      repository.findOne
        .mockResolvedValueOnce(null)
        .mockResolvedValueOnce(concurrentlyIssued);
      builder.mockResolvedValue({ credentialObject: {}, jws: 'creator.jws' });
      repository.save.mockRejectedValue({ code: '23505' });

      await expect(service.ensureCreatorCredential(creator)).resolves.toBe(
        concurrentlyIssued,
      );
      expect(repository.findOne).toHaveBeenCalledTimes(2);
    });
  });
});

describe('stripTransientFields', () => {
  it('removes every key starting with a double underscore', () => {
    expect(
      stripTransientFields({
        id: 'urn:uuid:credential',
        __keypairSnapshot: { derivedDidKey: EXTERNAL_DID_KEY },
        __acceptanceChallenge: { signingInput: 'header.payload' },
      }),
    ).toEqual({ id: 'urn:uuid:credential' });
  });

  it('tolerates a missing credential object', () => {
    expect(stripTransientFields(undefined)).toEqual({});
  });
});

describe('credential formatters', () => {
  const creatorWithIdentity = buildUser({
    id: CREATOR_ID,
    clerkRole: ClerkRole.Creator,
    name: 'Alice',
    didKey: 'did:key:zAlice',
    credentials: [
      buildCredential({
        id: 2,
        credentialType: CredentialType.EMail,
        credentialStatus: CredentialVerificationStatus.Pending,
        email: 'unverified@example.org',
      }),
      buildCredential({
        id: 3,
        credentialType: CredentialType.EMail,
        credentialStatus: CredentialVerificationStatus.Success,
        email: 'alice@example.org',
      }),
    ],
    createdConnections: [
      buildConnection({ id: 1, status: ConnectionStatus.Revoked }),
      buildConnection({ id: 2, status: ConnectionStatus.Accepted }),
      buildConnection({
        id: 3,
        issuerId: OTHER_ISSUER_ID,
        status: ConnectionStatus.Requested,
      }),
    ],
  });

  describe('formatIssuedCredential', () => {
    it('adds timestamps, the latest connection status and the creator identity', () => {
      const credential = buildCredential({
        user: creatorWithIdentity,
        credentialObject: {
          id: 'urn:uuid:credential',
          __acceptanceChallenge: { signingInput: 'header.payload' },
        },
      });

      const formatted = formatIssuedCredential(credential);

      expect(formatted).toMatchObject({
        id: '1',
        status: CredentialVerificationStatus.Success,
        type: CredentialType.Member,
        issuedAt: credential.createdAt,
        updatedAt: credential.updatedAt,
        revokedAt: null,
        revokedReason: null,
        connectionStatus: ConnectionStatus.Accepted,
        creator: {
          id: CREATOR_ID,
          name: 'Alice',
          email: 'alice@example.org',
          didKey: 'did:key:zAlice',
        },
      });
      expect(formatted.data.credentialObject).toEqual({
        id: 'urn:uuid:credential',
        proof: { type: 'JwtProof2020', jwt: credential.token },
      });
    });

    it('exposes the revocation of a revoked credential', () => {
      const revokedAt = new Date('2026-02-01T00:00:00.000Z');

      const formatted = formatIssuedCredential(
        buildCredential({
          user: creatorWithIdentity,
          credentialStatus: CredentialVerificationStatus.Revoked,
          revokedAt,
          revokedReason: 'Membership ended',
        }),
      );

      expect(formatted).toMatchObject({
        status: CredentialVerificationStatus.Revoked,
        revokedAt,
        revokedReason: 'Membership ended',
      });
    });

    it('reports a creator without verified e-mail or connection with nulls', () => {
      const formatted = formatIssuedCredential(
        buildCredential({
          user: buildUser({
            id: CREATOR_ID,
            name: 'Bob',
            didKey: 'did:key:zBob',
          }),
        }),
      );

      expect(formatted.connectionStatus).toBeNull();
      expect(formatted.creator).toEqual({
        id: CREATOR_ID,
        name: 'Bob',
        email: null,
        didKey: 'did:key:zBob',
      });
    });
  });

  describe('formatMemberCredential', () => {
    it('omits the revocation fields on an issued credential', () => {
      const formatted = formatMemberCredential(buildCredential({}));

      expect(formatted).not.toHaveProperty('revokedAt');
      expect(formatted).not.toHaveProperty('revokedReason');
    });

    it('exposes revokedAt and revokedReason on a revoked credential', () => {
      const revokedAt = new Date('2026-02-01T00:00:00.000Z');

      const formatted = formatMemberCredential(
        buildCredential({
          credentialStatus: CredentialVerificationStatus.Revoked,
          revokedAt,
          revokedReason: 'Membership ended',
        }),
      );

      expect(formatted).toMatchObject({
        status: CredentialVerificationStatus.Revoked,
        revokedAt,
        revokedReason: 'Membership ended',
      });
    });
  });

  describe('formatCreatorCredential', () => {
    it('exposes who verified the creator and the signed object', () => {
      const formatted = formatCreatorCredential(
        buildCredential({
          id: 4,
          credentialType: CredentialType.Creator,
          issuerId: null,
          value: PLATFORM_HOST,
          credentialObject: { type: ['VerifiableCreator'] },
        }),
      );

      expect(formatted).toEqual({
        id: '4',
        status: CredentialVerificationStatus.Success,
        type: CredentialType.Creator,
        data: {
          verifiedBy: PLATFORM_HOST,
          credentialObject: {
            type: ['VerifiableCreator'],
            proof: { type: 'JwtProof2020', jwt: 'header.payload.signature' },
          },
        },
      });
    });
  });
});
