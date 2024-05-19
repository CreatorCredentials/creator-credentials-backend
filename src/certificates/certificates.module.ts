import { Module } from '@nestjs/common';
import { CertificatesService } from './certificates.service';
import { HttpModule } from '@nestjs/axios';

@Module({
  imports: [HttpModule],
  providers: [CertificatesService],
  exports: [CertificatesService],
})
export class CertificatesModule {}
