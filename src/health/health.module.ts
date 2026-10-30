import { Module } from '@nestjs/common';
import { TerminusModule } from '@nestjs/terminus';
import { TrustStoreModule } from 'src/cert-challenge/trust-store/trust-store.module';
import { HealthController } from './health.controller';
import { TrustStoreHealthIndicator } from './trust-store.health';

@Module({
  imports: [TerminusModule, TrustStoreModule],
  controllers: [HealthController],
  providers: [TrustStoreHealthIndicator],
})
export class HealthModule {}
