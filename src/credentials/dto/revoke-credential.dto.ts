import { IsOptional, IsString, MaxLength } from 'class-validator';
import { REVOKED_REASON_MAX_LENGTH } from '../credentials.constants';

export class RevokeCredentialDto {
  @IsOptional()
  @IsString()
  @MaxLength(REVOKED_REASON_MAX_LENGTH)
  reason?: string;
}
