import { Controller, Get, VERSION_NEUTRAL } from '@nestjs/common';
import {
  HealthCheckService,
  HealthCheck,
  TypeOrmHealthIndicator,
} from '@nestjs/terminus';
import { TrustStoreHealthIndicator } from './trust-store.health';

@Controller({ version: VERSION_NEUTRAL, path: 'health' })
export class HealthController {
  constructor(
    private health: HealthCheckService,
    private db: TypeOrmHealthIndicator,
    private trustStore: TrustStoreHealthIndicator,
  ) {}

  @Get()
  @HealthCheck()
  check() {
    return this.health.check([
      () => this.db.pingCheck('database-dev'),
      () => this.trustStore.check('trustStore'),
    ]);
  }
}
