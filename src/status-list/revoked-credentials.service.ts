import { Injectable, Logger } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { IsNull, Repository } from 'typeorm';
import { Credential } from 'src/credentials/credential.entity';
import {
  PLATFORM_DID,
  signJWTWithX5c,
} from 'src/credentials/credentials.helpers';
import { resolveApiBaseUrl } from 'src/shared/app-base-url';
import { issuerDidOf } from 'src/shared/credential-object';
import { CredentialVerificationStatus } from 'src/shared/typings/CredentialVerificationStatus';
import {
  REVOKED_CREDENTIALS_PATH,
  REVOKED_CREDENTIALS_REGISTRY_TYPE,
  STATUS_LIST_ID,
  STATUS_LIST_PATH,
} from './status-list.constants';
import {
  RevokedCredentialRecord,
  RevokedCredentialsRegistry,
} from './status-list.types';

const REGISTRY_DESCRIPTION =
  'Credentials this platform issued before it adopted the W3C Bitstring ' +
  'Status List carry no credentialStatus entry, so their revocation cannot ' +
  'be read from a status list. This registry lists those of them that have ' +
  'been revoked, by credential id. Credentials with a credentialStatus entry ' +
  'are covered by the status list named in statusListCredential.';

/**
 * Signed registry of the revoked credentials that carry no status entry.
 * Built from the database on every request: the set is small and only
 * grows by hand-made revocations.
 */
@Injectable()
export class RevokedCredentialsService {
  private readonly logger = new Logger(RevokedCredentialsService.name);
  private readonly apiBaseUrl: string;

  constructor(
    @InjectRepository(Credential)
    private readonly credentials: Repository<Credential>,
  ) {
    this.apiBaseUrl = resolveApiBaseUrl((message) => this.logger.warn(message));
  }

  registryUrl(): string {
    return `${this.apiBaseUrl}${REVOKED_CREDENTIALS_PATH}`;
  }

  async getRegistry(): Promise<RevokedCredentialsRegistry> {
    const document = {
      id: this.registryUrl(),
      type: REVOKED_CREDENTIALS_REGISTRY_TYPE,
      issuer: PLATFORM_DID,
      generatedAt: new Date().toISOString(),
      description: REGISTRY_DESCRIPTION,
      statusListCredential: `${this.apiBaseUrl}${STATUS_LIST_PATH}/${STATUS_LIST_ID}`,
      revokedCredentials: await this.loadRevokedWithoutStatusEntry(),
    };
    const jwt = await signJWTWithX5c(document);
    return {
      registry: { ...document, proof: { type: 'JwtProof2020', jwt } },
      jwt,
    };
  }

  private async loadRevokedWithoutStatusEntry(): Promise<
    RevokedCredentialRecord[]
  > {
    const revoked = await this.credentials.find({
      select: { id: true, credentialObject: true, revokedAt: true },
      where: {
        credentialStatus: CredentialVerificationStatus.Revoked,
        statusListIndex: IsNull(),
      },
      order: { revokedAt: 'DESC' },
    });
    const records: RevokedCredentialRecord[] = [];
    for (const credential of revoked) {
      const record = toRecord(credential);
      if (record) {
        records.push(record);
      } else {
        this.logger.warn(
          `revoked credential ${credential.id} has no id in its credential object; left out of the registry`,
        );
      }
    }
    return records;
  }
}

function toRecord(credential: Credential): RevokedCredentialRecord | undefined {
  const object: Record<string, unknown> = credential.credentialObject ?? {};
  if (typeof object.id !== 'string') {
    return undefined;
  }
  return {
    id: object.id,
    issuer: issuerDidOf(object),
    revokedAt: credential.revokedAt ? credential.revokedAt.toISOString() : null,
  };
}
