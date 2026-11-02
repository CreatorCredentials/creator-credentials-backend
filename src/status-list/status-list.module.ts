import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { Credential } from 'src/credentials/credential.entity';
import { RevokedCredentialsController } from './revoked-credentials.controller';
import { RevokedCredentialsService } from './revoked-credentials.service';
import { StatusListController } from './status-list.controller';
import { StatusListService } from './status-list.service';

@Module({
  imports: [TypeOrmModule.forFeature([Credential])],
  providers: [StatusListService, RevokedCredentialsService],
  controllers: [StatusListController, RevokedCredentialsController],
  exports: [StatusListService],
})
export class StatusListModule {}
