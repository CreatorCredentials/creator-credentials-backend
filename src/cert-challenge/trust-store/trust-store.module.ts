import { Module } from '@nestjs/common';
import { HttpModule } from '@nestjs/axios';
import { TrustStoreService } from './trust-store.service';
import { TrustStoreRefreshService } from './trust-store.refresh';
import { XadesVerifier } from './eidas/xades-verifier';
import { LotlPivotBootstrap } from './eidas/pivot-bootstrap';
import { LotlLoaderService } from './eidas/lotl-loader.service';
import { TlLoaderService } from './eidas/tl-loader.service';
import { EidasPipelineService } from './eidas/eidas-pipeline.service';

@Module({
  imports: [HttpModule.register({ timeout: 30000 })],
  providers: [
    TrustStoreService,
    TrustStoreRefreshService,
    XadesVerifier,
    LotlPivotBootstrap,
    LotlLoaderService,
    TlLoaderService,
    EidasPipelineService,
  ],
  exports: [TrustStoreService, TrustStoreRefreshService],
})
export class TrustStoreModule {}
