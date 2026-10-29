import { Test, TestingModule } from '@nestjs/testing';
import { getRepositoryToken } from '@nestjs/typeorm';
import { NotFoundException } from '@nestjs/common';
import { Credential } from 'src/credentials/credential.entity';
import { CredentialsService } from 'src/credentials/credentials.service';
import { CredentialType } from 'src/shared/typings/CredentialType';
import { CredentialVerificationStatus } from 'src/shared/typings/CredentialVerificationStatus';
import { StatusListService } from 'src/status-list/status-list.service';
import { ClerkRole, User } from 'src/users/user.entity';
import { AdminService } from './admin.service';
import { ListAdminCredentialsQueryDto } from './dto/list-admin-credentials-query.dto';
import { ListAdminUsersQueryDto } from './dto/list-admin-users-query.dto';

const STATUS_LIST_URL = 'https://api.example.org/v1/status-lists/1';

function buildUser(overrides: Partial<User>): User {
  return Object.assign(new User(), {
    credentials: [],
    createdConnections: [],
    ...overrides,
  });
}

const issuer = buildUser({
  id: 10,
  clerkRole: ClerkRole.Issuer,
  name: 'Issuer Inc',
  domain: 'issuer.example',
});
const creator = buildUser({
  id: 20,
  clerkRole: ClerkRole.Creator,
  name: 'Alice',
  didKey: 'did:key:zAlice',
  credentials: [
    Object.assign(new Credential(), {
      credentialType: CredentialType.EMail,
      credentialStatus: CredentialVerificationStatus.Success,
      email: 'alice@example.org',
    }),
  ],
});
const admin = buildUser({
  id: 30,
  clerkRole: ClerkRole.Admin,
  name: 'Platform operator',
});

function buildCredential(overrides: Partial<Credential>): Credential {
  return Object.assign(new Credential(), {
    id: 1,
    issuerId: issuer.id,
    issuer,
    userId: creator.id,
    user: creator,
    credentialType: CredentialType.Member,
    credentialStatus: CredentialVerificationStatus.Success,
    credentialObject: { id: 'urn:uuid:credential' },
    token: 'header.payload.signature',
    value: 'did:web:issuer.example',
    createdAt: new Date('2026-01-01T00:00:00.000Z'),
    updatedAt: new Date('2026-01-02T00:00:00.000Z'),
    ...overrides,
  });
}

function credentialsQuery(
  overrides: Partial<ListAdminCredentialsQueryDto> = {},
): ListAdminCredentialsQueryDto {
  return Object.assign(new ListAdminCredentialsQueryDto(), overrides);
}

function usersQuery(
  overrides: Partial<ListAdminUsersQueryDto> = {},
): ListAdminUsersQueryDto {
  return Object.assign(new ListAdminUsersQueryDto(), overrides);
}

describe('AdminService', () => {
  const queryBuilder = {
    leftJoinAndSelect: jest.fn(),
    leftJoin: jest.fn(),
    loadRelationCountAndMap: jest.fn(),
    where: jest.fn(),
    andWhere: jest.fn(),
    orderBy: jest.fn(),
    addOrderBy: jest.fn(),
    skip: jest.fn(),
    take: jest.fn(),
    select: jest.fn(),
    addSelect: jest.fn(),
    groupBy: jest.fn(),
    getManyAndCount: jest.fn(),
    getOne: jest.fn(),
    getRawMany: jest.fn(),
  };
  const credentialsRepository = {
    createQueryBuilder: jest.fn(),
    count: jest.fn(),
  };
  const usersRepository = { createQueryBuilder: jest.fn() };
  const credentialsService = { revokeCredentialAsAdmin: jest.fn() };
  const statusList = { credentialUrl: jest.fn() };
  let service: AdminService;

  beforeEach(async () => {
    jest.resetAllMocks();
    for (const method of Object.keys(queryBuilder)) {
      if (!method.startsWith('get')) {
        queryBuilder[method].mockReturnValue(queryBuilder);
      }
    }
    credentialsRepository.createQueryBuilder.mockReturnValue(queryBuilder);
    usersRepository.createQueryBuilder.mockReturnValue(queryBuilder);
    statusList.credentialUrl.mockReturnValue(STATUS_LIST_URL);

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        AdminService,
        {
          provide: getRepositoryToken(Credential),
          useValue: credentialsRepository,
        },
        { provide: getRepositoryToken(User), useValue: usersRepository },
        { provide: CredentialsService, useValue: credentialsService },
        { provide: StatusListService, useValue: statusList },
      ],
    }).compile();

    service = module.get(AdminService);
  });

  describe('listCredentials', () => {
    it('pages with skip/take and reports total, page and pageSize', async () => {
      queryBuilder.getManyAndCount.mockResolvedValue([
        [buildCredential({})],
        57,
      ]);

      const page = await service.listCredentials(
        credentialsQuery({ page: 3, pageSize: 20 }),
      );

      expect(queryBuilder.skip).toHaveBeenCalledWith(40);
      expect(queryBuilder.take).toHaveBeenCalledWith(20);
      expect(page).toMatchObject({ total: 57, page: 3, pageSize: 20 });
      expect(page.items).toHaveLength(1);
    });

    it('searches creator and issuer name, e-mail and did:key with one ILIKE pattern', async () => {
      queryBuilder.getManyAndCount.mockResolvedValue([[], 0]);

      await service.listCredentials(credentialsQuery({ q: ' alice ' }));

      const [sql, parameters] = queryBuilder.andWhere.mock.calls.find(
        ([clause]) => clause.includes('ILIKE'),
      );
      expect(sql).toContain('creator.name ILIKE :q');
      expect(sql).toContain('creatorEmail.email ILIKE :q');
      expect(sql).toContain('creator.didKey ILIKE :q');
      expect(sql).toContain('issuer.name ILIKE :q');
      expect(sql).toContain('issuerEmail.email ILIKE :q');
      expect(sql).toContain('issuer.didKey ILIKE :q');
      expect(parameters).toEqual({ q: '%alice%' });
    });

    it('applies status, type and issuer filters only when given', async () => {
      queryBuilder.getManyAndCount.mockResolvedValue([[], 0]);

      await service.listCredentials(
        credentialsQuery({
          status: CredentialVerificationStatus.Revoked,
          issuerId: issuer.id,
        }),
      );

      expect(queryBuilder.andWhere).toHaveBeenCalledWith(
        'credential.credentialStatus = :status',
        { status: CredentialVerificationStatus.Revoked },
      );
      expect(queryBuilder.andWhere).toHaveBeenCalledWith(
        'credential.issuerId = :issuerId',
        { issuerId: issuer.id },
      );
      expect(queryBuilder.andWhere).not.toHaveBeenCalledWith(
        'credential.credentialType = :type',
        expect.anything(),
      );
    });

    it('formats the admin shape with issuer, revoker and status-list entry', async () => {
      queryBuilder.getManyAndCount.mockResolvedValue([
        [
          buildCredential({
            credentialStatus: CredentialVerificationStatus.Revoked,
            revokedAt: new Date('2026-02-01T00:00:00.000Z'),
            revokedBy: admin,
            revokedByUserId: admin.id,
            statusListIndex: 7,
          }),
          buildCredential({
            id: 2,
            credentialType: CredentialType.EMail,
            issuer: null,
            issuerId: null,
            statusListIndex: null,
          }),
        ],
        2,
      ]);

      const { items } = await service.listCredentials(credentialsQuery());

      expect(items[0]).toMatchObject({
        id: '1',
        status: CredentialVerificationStatus.Revoked,
        creator: { id: creator.id, name: 'Alice', email: 'alice@example.org' },
        issuer: { id: issuer.id, name: 'Issuer Inc', domain: 'issuer.example' },
        revokedBy: {
          id: admin.id,
          name: 'Platform operator',
          role: ClerkRole.Admin,
        },
        statusList: { credential: STATUS_LIST_URL, index: 7 },
      });
      expect(items[1]).toMatchObject({
        id: '2',
        issuer: null,
        revokedBy: null,
        statusList: null,
      });
    });
  });

  describe('getCredential', () => {
    it('answers 404 for an unknown id', async () => {
      queryBuilder.getOne.mockResolvedValue(null);

      await expect(service.getCredential(99)).rejects.toThrow(
        NotFoundException,
      );
    });
  });

  describe('revokeCredential', () => {
    it('delegates to the credentials service and returns the admin shape', async () => {
      credentialsService.revokeCredentialAsAdmin.mockResolvedValue(
        buildCredential({
          credentialStatus: CredentialVerificationStatus.Revoked,
          revokedAt: new Date('2026-02-01T00:00:00.000Z'),
          revokedReason: 'Terms violated',
          revokedBy: admin,
          revokedByUserId: admin.id,
        }),
      );

      const revoked = await service.revokeCredential(
        1,
        admin,
        'Terms violated',
      );

      expect(credentialsService.revokeCredentialAsAdmin).toHaveBeenCalledWith(
        1,
        admin,
        'Terms violated',
      );
      expect(revoked).toMatchObject({
        status: CredentialVerificationStatus.Revoked,
        revokedReason: 'Terms violated',
        revokedBy: { id: admin.id, role: ClerkRole.Admin },
      });
    });
  });

  describe('listUsers', () => {
    it('lists issuers and creators by default with their counts and verified e-mail', async () => {
      queryBuilder.getManyAndCount.mockResolvedValue([
        [
          Object.assign(buildUser({ ...creator }), {
            credentialCount: 3,
            issuedCredentialCount: 0,
          }),
        ],
        1,
      ]);

      const page = await service.listUsers(
        usersQuery({ page: 2, pageSize: 10 }),
      );

      expect(queryBuilder.where).toHaveBeenCalledWith(
        'user.clerkRole IN (:...roles)',
        { roles: [ClerkRole.Issuer, ClerkRole.Creator] },
      );
      expect(queryBuilder.skip).toHaveBeenCalledWith(10);
      expect(page.items[0]).toMatchObject({
        id: creator.id,
        role: ClerkRole.Creator,
        email: 'alice@example.org',
        counts: { credentials: 3, issuedCredentials: 0 },
      });
    });

    it('narrows to one role and searches when asked', async () => {
      queryBuilder.getManyAndCount.mockResolvedValue([[], 0]);

      await service.listUsers(usersQuery({ role: ClerkRole.Issuer, q: 'inc' }));

      expect(queryBuilder.where).toHaveBeenCalledWith(
        'user.clerkRole IN (:...roles)',
        { roles: [ClerkRole.Issuer] },
      );
      expect(queryBuilder.andWhere).toHaveBeenCalledWith(
        expect.stringContaining('user.name ILIKE :q'),
        { q: '%inc%' },
      );
    });
  });

  describe('getStats', () => {
    it('counts users by role, credentials by type and status, and recent revocations', async () => {
      queryBuilder.getRawMany
        .mockResolvedValueOnce([
          { key: ClerkRole.Issuer, count: '2' },
          { key: ClerkRole.Creator, count: '5' },
        ])
        .mockResolvedValueOnce([{ key: CredentialType.Member, count: '4' }])
        .mockResolvedValueOnce([
          { key: CredentialVerificationStatus.Success, count: '3' },
          { key: CredentialVerificationStatus.Revoked, count: '1' },
        ]);
      credentialsRepository.count.mockResolvedValue(1);

      const stats = await service.getStats();

      expect(stats).toMatchObject({
        users: { issuer: 2, creator: 5 },
        credentials: {
          byType: { MEMBER: 4 },
          byStatus: { SUCCESS: 3, REVOKED: 1 },
        },
        revocationsLast30Days: 1,
      });
      expect(credentialsRepository.count).toHaveBeenCalledWith({
        where: expect.objectContaining({
          credentialStatus: CredentialVerificationStatus.Revoked,
        }),
      });
    });
  });
});
