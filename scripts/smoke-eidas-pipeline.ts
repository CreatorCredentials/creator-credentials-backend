/**
 * Manual smoke test for the eIDAS pipeline. Boots only the trust-store and
 * cert-challenge modules (no DB), runs a full LOTL → country TL refresh, then
 * validates the LICCIUM.pem cert against the resulting trust store.
 *
 *     pnpm ts-node scripts/smoke-eidas-pipeline.ts
 *
 * Prints pass/fail per step. Useful when verifying changes to the pipeline.
 */
import 'reflect-metadata';
import * as fs from 'fs';
import * as path from 'path';
import { Test } from '@nestjs/testing';
import { TrustStoreModule } from '../src/cert-challenge/trust-store/trust-store.module';
import { TrustStoreRefreshService } from '../src/cert-challenge/trust-store/trust-store.refresh';
import { TrustStoreService } from '../src/cert-challenge/trust-store/trust-store.service';
import { CertValidatorService } from '../src/cert-challenge/validation/cert-validator.service';

async function main() {
  const moduleRef = await Test.createTestingModule({
    imports: [TrustStoreModule],
    providers: [CertValidatorService],
  }).compile();

  const refresh = moduleRef.get(TrustStoreRefreshService);
  const store = moduleRef.get(TrustStoreService);
  const validator = moduleRef.get(CertValidatorService);

  console.log('[1/3] Refreshing trust store from EU LOTL…');
  await refresh.refresh();

  const state = store.getState();
  if (state.status !== 'ready') {
    console.error('Trust store did not become ready:', state);
    process.exit(1);
  }
  console.log(`[1/3] OK: ${state.anchorCount} anchors loaded`);

  const liccPemPath = path.resolve(
    process.cwd(),
    'certificates',
    'LICCIUM.pem',
  );
  if (!fs.existsSync(liccPemPath)) {
    console.warn(`[2/3] SKIP: ${liccPemPath} not found`);
    return;
  }
  const pem = fs.readFileSync(liccPemPath, 'utf8');

  console.log('[2/3] Validating LICCIUM.pem against trust store…');
  const result = await validator.validateLeafPem(pem);
  if ('matchedAnchor' in result) {
    console.log(
      `[2/3] OK: matched anchor ${result.matchedAnchor.subject} (${result.matchedAnchor.country})`,
    );
  } else {
    console.error(`[2/3] FAIL: ${result.reason}`);
  }

  console.log('[3/3] Validating a tampered LICCIUM cert…');
  const tampered = tamperPem(pem);
  const tamperedResult = await validator.validateLeafPem(tampered);
  if ('reason' in tamperedResult) {
    console.log(`[3/3] OK: tamper rejected: ${tamperedResult.reason}`);
  } else {
    console.error('[3/3] FAIL: tamper accepted!');
  }

  await moduleRef.close();
}

function tamperPem(pem: string): string {
  // Flip a single base64 character in the body of the PEM. This will modify
  // the DER bytes deterministically — most flips land in the CA signature
  // bytes, which is exactly the case we want to detect.
  const lines = pem.trim().split('\n');
  const bodyIdx = lines.findIndex((l) => !l.startsWith('-')) + 5;
  const target = lines[bodyIdx];
  if (!target) return pem;
  const flipped = target.slice(0, 10) + (target[10] === 'A' ? 'B' : 'A') + target.slice(11);
  lines[bodyIdx] = flipped;
  return lines.join('\n') + '\n';
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
