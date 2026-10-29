import { randomInt } from 'crypto';
import { Injectable, Logger } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Credential } from 'src/credentials/credential.entity';
import {
  PLATFORM_DID,
  signJWTWithX5c,
} from 'src/credentials/credentials.helpers';
import { CredentialVerificationStatus } from 'src/shared/typings/CredentialVerificationStatus';
import { resolveApiBaseUrl } from 'src/shared/app-base-url';
import { decodeBitstring, encodeBitstring, isBitSet } from './bitstring';
import {
  STATUS_LIST_ALLOCATION_ATTEMPTS,
  STATUS_LIST_CACHE_TTL_MS,
  STATUS_LIST_CAPACITY_WARNING_RATIO,
  STATUS_LIST_CREDENTIAL_TYPE,
  STATUS_LIST_ENTRY_TYPE,
  STATUS_LIST_ID,
  STATUS_LIST_PATH,
  STATUS_LIST_PURPOSE,
  STATUS_LIST_SIZE,
  STATUS_LIST_SLOT_TABLE,
  STATUS_LIST_SUBJECT_TYPE,
  STATUS_LIST_VALIDITY_MS,
  VC_JWT_TYP,
} from './status-list.constants';
import {
  CredentialStatusEntry,
  ReservedStatusListEntry,
  StatusListCredential,
} from './status-list.types';

type CachedList = { list: Promise<StatusListCredential>; expiresAt: number };

export class StatusListFullError extends Error {
  constructor() {
    super(`status list ${STATUS_LIST_ID} has no free index left`);
  }
}

/**
 * The platform's revocation list: one Bitstring Status List whose bit `i` is
 * set while the credential holding index `i` is REVOKED. Indices are drawn
 * at random and never reused; the signed list is rebuilt at most once per
 * cache period, or earlier when a revocation invalidates it.
 */
@Injectable()
export class StatusListService {
  private readonly logger = new Logger(StatusListService.name);
  private readonly apiBaseUrl: string;
  private cache: CachedList | null = null;

  constructor(
    @InjectRepository(Credential)
    private readonly credentialsRepository: Repository<Credential>,
  ) {
    this.apiBaseUrl = resolveApiBaseUrl((message) => this.logger.warn(message));
  }

  /** URL of the status list credential; the `statusListCredential` of every entry. */
  credentialUrl(): string {
    return `${this.apiBaseUrl}${STATUS_LIST_PATH}/${STATUS_LIST_ID}`;
  }

  isLocalListUrl(url: string): boolean {
    return url === this.credentialUrl();
  }

  entryFor(index: number): CredentialStatusEntry {
    const statusListCredential = this.credentialUrl();
    return {
      id: `${statusListCredential}#${index}`,
      type: STATUS_LIST_ENTRY_TYPE,
      statusPurpose: STATUS_LIST_PURPOSE,
      statusListIndex: String(index),
      statusListCredential,
    };
  }

  /**
   * A free index chosen at random; each call consumes one entry of the list
   * for good. Random draws are retried a few times before a scan for any
   * free index, so a nearly full list still allocates.
   */
  async allocateIndex(): Promise<number> {
    for (
      let attempt = 0;
      attempt < STATUS_LIST_ALLOCATION_ATTEMPTS;
      attempt++
    ) {
      const index = await this.claimSlot(randomInt(STATUS_LIST_SIZE));
      if (index !== undefined) {
        return index;
      }
    }
    return this.claimAnyFreeSlot();
  }

  async reserveEntry(): Promise<ReservedStatusListEntry> {
    const index = await this.allocateIndex();
    return { index, credentialStatus: this.entryFor(index) };
  }

  async getCredential(): Promise<StatusListCredential> {
    const now = Date.now();
    if (!this.cache || this.cache.expiresAt <= now) {
      this.cache = {
        list: this.buildCredential(),
        expiresAt: now + STATUS_LIST_CACHE_TTL_MS,
      };
      this.cache.list.catch(() => this.invalidate());
    }
    return this.cache.list;
  }

  async isRevoked(index: number): Promise<boolean> {
    const { credential } = await this.getCredential();
    const subject = credential.credentialSubject as { encodedList: string };
    return isBitSet(decodeBitstring(subject.encodedList), index);
  }

  /** Drops the cached list so the next read reflects the database. */
  invalidate(): void {
    this.cache = null;
  }

  /** The index if it was still free, otherwise undefined. */
  private async claimSlot(index: number): Promise<number | undefined> {
    const rows: { index: number }[] = await this.credentialsRepository.query(
      `INSERT INTO "${STATUS_LIST_SLOT_TABLE}" ("index") VALUES ($1) ON CONFLICT DO NOTHING RETURNING "index"`,
      [index],
    );
    return rows.length ? Number(rows[0].index) : undefined;
  }

  private async claimAnyFreeSlot(): Promise<number> {
    await this.warnWhenNearlyFull();
    const rows: { index: number }[] = await this.credentialsRepository.query(
      `INSERT INTO "${STATUS_LIST_SLOT_TABLE}" ("index")
       SELECT free.index FROM generate_series(0, $1) AS free(index)
       WHERE NOT EXISTS (SELECT 1 FROM "${STATUS_LIST_SLOT_TABLE}" used WHERE used.index = free.index)
       ORDER BY random() LIMIT 1
       ON CONFLICT DO NOTHING RETURNING "index"`,
      [STATUS_LIST_SIZE - 1],
    );
    if (!rows.length) {
      throw new StatusListFullError();
    }
    return Number(rows[0].index);
  }

  private async warnWhenNearlyFull(): Promise<void> {
    const [row]: { used: string }[] = await this.credentialsRepository.query(
      `SELECT COUNT(*) AS used FROM "${STATUS_LIST_SLOT_TABLE}"`,
    );
    const used = Number(row.used);
    if (used >= STATUS_LIST_SIZE * STATUS_LIST_CAPACITY_WARNING_RATIO) {
      this.logger.warn(
        `status list ${STATUS_LIST_ID}: ${used} of ${STATUS_LIST_SIZE} indices used; plan a second list`,
      );
    }
  }

  private async buildCredential(): Promise<StatusListCredential> {
    const revokedIndices = await this.loadRevokedIndices();
    const builtAt = new Date();
    const url = this.credentialUrl();
    const credentialObject = {
      '@context': ['https://www.w3.org/ns/credentials/v2'],
      id: url,
      type: ['VerifiableCredential', STATUS_LIST_CREDENTIAL_TYPE],
      issuer: PLATFORM_DID,
      validFrom: builtAt.toISOString(),
      validUntil: new Date(
        builtAt.getTime() + STATUS_LIST_VALIDITY_MS,
      ).toISOString(),
      credentialSubject: {
        id: `${url}#list`,
        type: STATUS_LIST_SUBJECT_TYPE,
        statusPurpose: STATUS_LIST_PURPOSE,
        encodedList: encodeBitstring(revokedIndices),
        ttl: STATUS_LIST_CACHE_TTL_MS,
      },
    };
    const jwt = await signJWTWithX5c(credentialObject, undefined, {
      typ: VC_JWT_TYP,
    });
    return {
      credential: {
        ...credentialObject,
        proof: { type: 'JwtProof2020', jwt },
      },
      jwt,
    };
  }

  private async loadRevokedIndices(): Promise<number[]> {
    const rows: { index: number }[] = await this.credentialsRepository
      .createQueryBuilder('credential')
      .select('credential.statusListIndex', 'index')
      .where('credential.credentialStatus = :revoked', {
        revoked: CredentialVerificationStatus.Revoked,
      })
      .andWhere('credential.statusListIndex IS NOT NULL')
      .getRawMany();
    return rows.map((row) => Number(row.index));
  }
}
