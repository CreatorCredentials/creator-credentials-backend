import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { Credential } from 'src/credentials/credential.entity';
import { CredentialsModule } from 'src/credentials/credentials.module';
import { StatusListModule } from 'src/status-list/status-list.module';
import { User } from 'src/users/user.entity';
import { UsersModule } from 'src/users/users.module';
import { AdminController } from './admin.controller';
import { AdminService } from './admin.service';

@Module({
  imports: [
    TypeOrmModule.forFeature([Credential, User]),
    UsersModule,
    CredentialsModule,
    StatusListModule,
  ],
  providers: [AdminService],
  controllers: [AdminController],
})
export class AdminModule {}
