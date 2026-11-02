import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Credential } from 'src/credentials/credential.entity';
import { CredentialVerificationStatus } from 'src/shared/typings/CredentialVerificationStatus';

/** `unknown`: the platform never issued a credential signed as this token. */
export type IssuedCredentialState = 'valid' | 'revoked' | 'unknown';

/**
 * The platform's own records of the credentials it issued. A credential
 * issued before status lists carries no `credentialStatus` entry, so its
 * revocation is known nowhere else.
 */
@Injectable()
export class IssuedCredentialRecordsService {
  constructor(
    @InjectRepository(Credential)
    private readonly credentials: Repository<Credential>,
  ) {}

  /** State of the credential that was signed as exactly this compact token. */
  async stateOfToken(token: string): Promise<IssuedCredentialState> {
    const record = await this.credentials.findOne({
      where: { token },
      select: { id: true, credentialStatus: true },
    });
    return record ? stateOf(record.credentialStatus) : 'unknown';
  }
}

function stateOf(status: CredentialVerificationStatus): IssuedCredentialState {
  switch (status) {
    case CredentialVerificationStatus.Revoked:
      return 'revoked';
    case CredentialVerificationStatus.Success:
      return 'valid';
    default:
      return 'unknown';
  }
}
