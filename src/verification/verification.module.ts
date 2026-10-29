import { Module } from '@nestjs/common';
import { HttpModule } from '@nestjs/axios';
import { StatusListModule } from 'src/status-list/status-list.module';
import { VerificationController } from './verification.controller';
import { VerificationService } from './verification.service';

@Module({
  imports: [HttpModule, StatusListModule],
  providers: [VerificationService],
  controllers: [VerificationController],
})
export class VerificationModule {}
