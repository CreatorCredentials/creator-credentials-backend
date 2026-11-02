import { Module } from '@nestjs/common';
import { HttpModule } from '@nestjs/axios';
import { TypeOrmModule } from '@nestjs/typeorm';
import { Credential } from 'src/credentials/credential.entity';
import { StatusListModule } from 'src/status-list/status-list.module';
import { IssuedCredentialRecordsService } from './issued-credential-records.service';
import { VerificationController } from './verification.controller';
import { VerificationService } from './verification.service';

@Module({
  imports: [
    HttpModule,
    StatusListModule,
    TypeOrmModule.forFeature([Credential]),
  ],
  providers: [VerificationService, IssuedCredentialRecordsService],
  controllers: [VerificationController],
})
export class VerificationModule {}
