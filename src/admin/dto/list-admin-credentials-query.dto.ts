import { Type } from 'class-transformer';
import { IsEnum, IsInt, IsOptional } from 'class-validator';
import { CredentialType } from 'src/shared/typings/CredentialType';
import { CredentialVerificationStatus } from 'src/shared/typings/CredentialVerificationStatus';
import { PageQueryDto } from './page-query.dto';

export class ListAdminCredentialsQueryDto extends PageQueryDto {
  @IsOptional()
  @IsEnum(CredentialVerificationStatus)
  status?: CredentialVerificationStatus;

  @IsOptional()
  @IsEnum(CredentialType)
  type?: CredentialType;

  @IsOptional()
  @Type(() => Number)
  @IsInt()
  issuerId?: number;
}
