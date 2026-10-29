import { Injectable, NotFoundException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { MoreThanOrEqual, Repository, SelectQueryBuilder } from 'typeorm';
import { Credential } from 'src/credentials/credential.entity';
import { CredentialsService } from 'src/credentials/credentials.service';
import { formatAdminCredential } from 'src/credentials/credentials.formatters';
import { AdminCredential } from 'src/shared/typings/Credentials';
import { CredentialType } from 'src/shared/typings/CredentialType';
import { CredentialVerificationStatus } from 'src/shared/typings/CredentialVerificationStatus';
import { StatusListService } from 'src/status-list/status-list.service';
import { ClerkRole, User } from 'src/users/user.entity';
import { countsByKey, formatAdminUser } from './admin.formatters';
import { AdminStats, AdminUser, UserWithCounts } from './admin.types';
import { ListAdminCredentialsQueryDto } from './dto/list-admin-credentials-query.dto';
import { ListAdminUsersQueryDto } from './dto/list-admin-users-query.dto';
import { Page, PageQueryDto } from './dto/page-query.dto';

const REVOCATION_STATS_WINDOW_DAYS = 30;
const MS_PER_DAY = 24 * 60 * 60 * 1000;
/** Roles listed by default on GET admin/users: the platform's own accounts are not users of it. */
const LISTED_ROLES = [ClerkRole.Issuer, ClerkRole.Creator];

/** Platform-wide reads and the admin revoke; every route is admin-only. */
@Injectable()
export class AdminService {
  constructor(
    @InjectRepository(Credential)
    private readonly credentialsRepository: Repository<Credential>,
    @InjectRepository(User)
    private readonly usersRepository: Repository<User>,
    private readonly credentialsService: CredentialsService,
    private readonly statusList: StatusListService,
  ) {}

  async listCredentials(
    query: ListAdminCredentialsQueryDto,
  ): Promise<Page<AdminCredential>> {
    const builder = this.adminCredentialQuery();
    if (query.status) {
      builder.andWhere('credential.credentialStatus = :status', {
        status: query.status,
      });
    }
    if (query.type) {
      builder.andWhere('credential.credentialType = :type', {
        type: query.type,
      });
    }
    if (query.issuerId) {
      builder.andWhere('credential.issuerId = :issuerId', {
        issuerId: query.issuerId,
      });
    }
    if (query.q) {
      builder.andWhere(
        `(creator.name ILIKE :q OR creatorEmail.email ILIKE :q OR creator.didKey ILIKE :q OR creator.externalDidKey ILIKE :q
          OR issuer.name ILIKE :q OR issuerEmail.email ILIKE :q OR issuer.didKey ILIKE :q)`,
        { q: containsPattern(query.q) },
      );
    }

    const [credentials, total] = await builder
      .orderBy('credential.createdAt', 'DESC')
      .addOrderBy('credential.id', 'DESC')
      .skip(offset(query))
      .take(query.pageSize)
      .getManyAndCount();

    return {
      items: credentials.map((credential) => this.format(credential)),
      total,
      page: query.page,
      pageSize: query.pageSize,
    };
  }

  async getCredential(credentialId: number): Promise<AdminCredential> {
    const credential = await this.adminCredentialQuery()
      .andWhere('credential.id = :credentialId', { credentialId })
      .getOne();
    if (!credential) {
      throw new NotFoundException('Credential not found.');
    }
    return this.format(credential);
  }

  async revokeCredential(
    credentialId: number,
    admin: User,
    reason?: string,
  ): Promise<AdminCredential> {
    const revoked = await this.credentialsService.revokeCredentialAsAdmin(
      credentialId,
      admin,
      reason,
    );
    return this.format(revoked);
  }

  async listUsers(query: ListAdminUsersQueryDto): Promise<Page<AdminUser>> {
    const builder = this.usersRepository
      .createQueryBuilder('user')
      .leftJoinAndSelect(
        'user.credentials',
        'email',
        'email.credentialType = :emailType AND email.credentialStatus = :issued',
        {
          emailType: CredentialType.EMail,
          issued: CredentialVerificationStatus.Success,
        },
      )
      .loadRelationCountAndMap('user.credentialCount', 'user.credentials')
      .loadRelationCountAndMap(
        'user.issuedCredentialCount',
        'user.issuedCredentials',
      )
      .where('user.clerkRole IN (:...roles)', {
        roles: query.role ? [query.role] : LISTED_ROLES,
      });
    if (query.q) {
      builder.andWhere(
        `(user.name ILIKE :q OR email.email ILIKE :q OR user.didKey ILIKE :q OR user.externalDidKey ILIKE :q
          OR user.domain ILIKE :q OR user.organizationName ILIKE :q)`,
        { q: containsPattern(query.q) },
      );
    }

    const [users, total] = await builder
      .orderBy('user.createdAt', 'DESC')
      .addOrderBy('user.id', 'DESC')
      .skip(offset(query))
      .take(query.pageSize)
      .getManyAndCount();

    return {
      items: (users as UserWithCounts[]).map(formatAdminUser),
      total,
      page: query.page,
      pageSize: query.pageSize,
    };
  }

  async getStats(): Promise<AdminStats> {
    const since = new Date(
      Date.now() - REVOCATION_STATS_WINDOW_DAYS * MS_PER_DAY,
    );
    const [usersByRole, byType, byStatus, revocationsLast30Days] =
      await Promise.all([
        this.countGroupedBy(this.usersRepository, 'user', 'clerkRole'),
        this.countGroupedBy(
          this.credentialsRepository,
          'credential',
          'credentialType',
        ),
        this.countGroupedBy(
          this.credentialsRepository,
          'credential',
          'credentialStatus',
        ),
        this.credentialsRepository.count({
          where: {
            credentialStatus: CredentialVerificationStatus.Revoked,
            revokedAt: MoreThanOrEqual(since),
          },
        }),
      ]);

    return {
      users: usersByRole,
      credentials: { byType, byStatus },
      revocationsLast30Days,
      generatedAt: new Date().toISOString(),
    };
  }

  /**
   * Every credential with what the admin shape renders: creator with its
   * SUCCESS EMAIL row and connections, issuer, revoker. The issuer's e-mail
   * is joined for search only.
   */
  private adminCredentialQuery(): SelectQueryBuilder<Credential> {
    const emailJoin = {
      emailType: CredentialType.EMail,
      issued: CredentialVerificationStatus.Success,
    };
    return this.credentialsRepository
      .createQueryBuilder('credential')
      .leftJoinAndSelect('credential.user', 'creator')
      .leftJoinAndSelect('creator.createdConnections', 'connection')
      .leftJoinAndSelect(
        'creator.credentials',
        'creatorEmail',
        'creatorEmail.credentialType = :emailType AND creatorEmail.credentialStatus = :issued',
        emailJoin,
      )
      .leftJoinAndSelect('credential.issuer', 'issuer')
      .leftJoin(
        'issuer.credentials',
        'issuerEmail',
        'issuerEmail.credentialType = :emailType AND issuerEmail.credentialStatus = :issued',
        emailJoin,
      )
      .leftJoinAndSelect('credential.revokedBy', 'revokedBy');
  }

  private format(credential: Credential): AdminCredential {
    return formatAdminCredential(credential, this.statusList.credentialUrl());
  }

  private async countGroupedBy<T>(
    repository: Repository<T>,
    alias: string,
    property: string,
  ): Promise<Record<string, number>> {
    const rows = await repository
      .createQueryBuilder(alias)
      .select(`${alias}.${property}`, 'key')
      .addSelect('COUNT(*)', 'count')
      .groupBy(`${alias}.${property}`)
      .getRawMany();
    return countsByKey(rows);
  }
}

function containsPattern(search: string): string {
  return `%${search.trim()}%`;
}

function offset(query: PageQueryDto): number {
  return (query.page - 1) * query.pageSize;
}
