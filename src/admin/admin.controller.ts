import {
  Body,
  Controller,
  Get,
  Param,
  ParseIntPipe,
  Post,
  Query,
  UseGuards,
  ValidationPipe,
} from '@nestjs/common';
import { RevokeCredentialDto } from 'src/credentials/dto/revoke-credential.dto';
import { AuthGuard } from 'src/users/guards/clerk-user.guard';
import { Roles } from 'src/users/guards/roles.decorator';
import { RolesGuard } from 'src/users/guards/roles.guard';
import { GetUser } from 'src/users/get-user.decorator';
import { ClerkRole, User } from 'src/users/user.entity';
import { AdminService } from './admin.service';
import { ListAdminCredentialsQueryDto } from './dto/list-admin-credentials-query.dto';
import { ListAdminUsersQueryDto } from './dto/list-admin-users-query.dto';

const queryPipe = new ValidationPipe({ transform: true, whitelist: true });
const bodyPipe = new ValidationPipe({ whitelist: true });

@Controller('admin')
@UseGuards(AuthGuard, RolesGuard)
@Roles(ClerkRole.Admin)
export class AdminController {
  constructor(private readonly adminService: AdminService) {}

  @Get('credentials')
  listCredentials(@Query(queryPipe) query: ListAdminCredentialsQueryDto) {
    return this.adminService.listCredentials(query);
  }

  @Get('credentials/:id')
  getCredential(@Param('id', ParseIntPipe) id: number) {
    return this.adminService.getCredential(id);
  }

  @Post('credentials/:id/revoke')
  revokeCredential(
    @GetUser() admin: User,
    @Param('id', ParseIntPipe) id: number,
    @Body(bodyPipe) body: RevokeCredentialDto,
  ) {
    return this.adminService.revokeCredential(id, admin, body.reason);
  }

  @Get('users')
  listUsers(@Query(queryPipe) query: ListAdminUsersQueryDto) {
    return this.adminService.listUsers(query);
  }

  @Get('stats')
  getStats() {
    return this.adminService.getStats();
  }
}
