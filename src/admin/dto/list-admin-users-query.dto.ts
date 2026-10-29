import { IsEnum, IsOptional } from 'class-validator';
import { ClerkRole } from 'src/users/user.entity';
import { PageQueryDto } from './page-query.dto';

export class ListAdminUsersQueryDto extends PageQueryDto {
  @IsOptional()
  @IsEnum(ClerkRole)
  role?: ClerkRole;
}
