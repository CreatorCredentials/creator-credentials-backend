import { Test, TestingModule } from '@nestjs/testing';
import { getRepositoryToken } from '@nestjs/typeorm';
import { Credential } from 'src/credentials/credential.entity';
import { CredentialVerificationStatus } from 'src/shared/typings/CredentialVerificationStatus';
import {
  leafCertificateOf,
  parseCompactJws,
  verifyJwsSignature,
} from 'src/verification/jws';
import { decodeBitstring, isBitSet } from './bitstring';
import {
  STATUS_LIST_CACHE_TTL_MS,
  STATUS_LIST_SIZE,
} from './status-list.constants';
import { StatusListService } from './status-list.service';
import {
  EphemeralPlatformSigner,
  PLATFORM_DID,
  installEphemeralPlatformSigner,
} from '../../test/support/platform-signer';

const API_BASE_URL = 'https://api.example.org';
const STATUS_LIST_URL = `${API_BASE_URL}/v1/status-lists/1`;
const REVOKED_INDICES = [3, 4096];

describe('StatusListService', () => {
  const queryBuilder = {
    select: jest.fn(),
    where: jest.fn(),
    andWhere: jest.fn(),
    getRawMany: jest.fn(),
  };
  const repository = { query: jest.fn(), createQueryBuilder: jest.fn() };
  let service: StatusListService;
  let platformSigner: EphemeralPlatformSigner;

  beforeAll(async () => {
    process.env.API_BASE_URL = `${API_BASE_URL}/`;
    platformSigner = await installEphemeralPlatformSigner();
  });

  afterAll(() => {
    delete process.env.API_BASE_URL;
    platformSigner.cleanup();
  });

  beforeEach(async () => {
    jest.resetAllMocks();
    jest.useRealTimers();
    repository.createQueryBuilder.mockReturnValue(queryBuilder);
    queryBuilder.select.mockReturnValue(queryBuilder);
    queryBuilder.where.mockReturnValue(queryBuilder);
    queryBuilder.andWhere.mockReturnValue(queryBuilder);
    queryBuilder.getRawMany.mockResolvedValue(
      REVOKED_INDICES.map((index) => ({ index: String(index) })),
    );

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        StatusListService,
        { provide: getRepositoryToken(Credential), useValue: repository },
      ],
    }).compile();
    service = module.get(StatusListService);
  });

  it('falls back to APP_BASE_URL when API_BASE_URL is not set', async () => {
    delete process.env.API_BASE_URL;
    process.env.APP_BASE_URL = 'https://app.example.org';
    try {
      const module: TestingModule = await Test.createTestingModule({
        providers: [
          StatusListService,
          { provide: getRepositoryToken(Credential), useValue: repository },
        ],
      }).compile();

      expect(module.get(StatusListService).credentialUrl()).toBe(
        'https://app.example.org/v1/status-lists/1',
      );
    } finally {
      process.env.API_BASE_URL = `${API_BASE_URL}/`;
      delete process.env.APP_BASE_URL;
    }
  });

  describe('index allocation', () => {
    it('claims a random slot of the list and returns it', async () => {
      repository.query.mockImplementation(
        async (_sql: string, [index]: [number]) => [{ index: String(index) }],
      );

      const index = await service.allocateIndex();

      expect(index).toBeGreaterThanOrEqual(0);
      expect(index).toBeLessThan(STATUS_LIST_SIZE);
      expect(repository.query).toHaveBeenCalledTimes(1);
      expect(repository.query.mock.calls[0][0]).toContain(
        'INSERT INTO "credential_status_list_slot"',
      );
      expect(repository.query.mock.calls[0][1]).toEqual([index]);
    });

    it('draws again when the random slot is already taken', async () => {
      repository.query
        .mockResolvedValueOnce([])
        .mockResolvedValueOnce([])
        .mockResolvedValueOnce([{ index: '4242' }]);

      await expect(service.allocateIndex()).resolves.toBe(4242);

      expect(repository.query).toHaveBeenCalledTimes(3);
    });

    it('falls back to a scan for any free slot when random draws keep colliding', async () => {
      repository.query.mockImplementation(async (sql: string) => {
        if (sql.includes('COUNT(*)')) return [{ used: '131000' }];
        if (sql.includes('generate_series')) return [{ index: '7' }];
        return [];
      });

      await expect(service.allocateIndex()).resolves.toBe(7);

      const scanCall = repository.query.mock.calls.find(([sql]) =>
        sql.includes('generate_series'),
      );
      expect(scanCall[1]).toEqual([STATUS_LIST_SIZE - 1]);
    });

    it('fails loudly when the list has no free slot left', async () => {
      repository.query.mockImplementation(async (sql: string) =>
        sql.includes('COUNT(*)') ? [{ used: String(STATUS_LIST_SIZE) }] : [],
      );

      await expect(service.allocateIndex()).rejects.toThrow(
        'no free index left',
      );
    });

    it('hands out distinct indices on consecutive reservations', async () => {
      repository.query
        .mockResolvedValueOnce([{ index: '0' }])
        .mockResolvedValueOnce([{ index: '1' }]);

      const [first, second] = await Promise.all([
        service.reserveEntry(),
        service.reserveEntry(),
      ]);

      expect(first.index).not.toBe(second.index);
      expect(first.credentialStatus).toEqual({
        id: `${STATUS_LIST_URL}#0`,
        type: 'BitstringStatusListEntry',
        statusPurpose: 'revocation',
        statusListIndex: '0',
        statusListCredential: STATUS_LIST_URL,
      });
    });
  });

  describe('getCredential', () => {
    it('serves a BitstringStatusListCredential with the revoked bits set', async () => {
      const { credential } = await service.getCredential();

      expect(credential).toMatchObject({
        '@context': ['https://www.w3.org/ns/credentials/v2'],
        id: STATUS_LIST_URL,
        type: ['VerifiableCredential', 'BitstringStatusListCredential'],
        issuer: PLATFORM_DID,
        credentialSubject: {
          id: `${STATUS_LIST_URL}#list`,
          type: 'BitstringStatusList',
          statusPurpose: 'revocation',
        },
        proof: { type: 'JwtProof2020' },
      });
      const validFrom = new Date(credential.validFrom as string).getTime();
      const validUntil = new Date(credential.validUntil as string).getTime();
      expect(validUntil - validFrom).toBe(24 * 60 * 60 * 1000);

      const subject = credential.credentialSubject as { encodedList: string };
      const bits = decodeBitstring(subject.encodedList);
      expect(bits.length * 8).toBe(STATUS_LIST_SIZE);
      expect(isBitSet(bits, 3)).toBe(true);
      expect(isBitSet(bits, 4096)).toBe(true);
      expect(isBitSet(bits, 2)).toBe(false);
      expect(queryBuilder.where).toHaveBeenCalledWith(
        'credential.credentialStatus = :revoked',
        { revoked: CredentialVerificationStatus.Revoked },
      );
    });

    it('signs the list with the platform certificate', async () => {
      const { credential, jwt } = await service.getCredential();

      const jws = parseCompactJws(jwt);
      const certificate = leafCertificateOf(jws.header);
      expect(certificate.subject).toContain(`CN=${PLATFORM_DID}`);
      expect(verifyJwsSignature(jws, certificate)).toBe(true);
      expect(jws.header.typ).toBe('vc+jwt');
      expect(jws.payload.credentialSubject).toEqual(
        credential.credentialSubject,
      );
      expect((credential.proof as { jwt: string }).jwt).toBe(jwt);
    });

    it('tells verifiers how long they may cache the list', async () => {
      const { credential } = await service.getCredential();

      expect((credential.credentialSubject as { ttl: number }).ttl).toBe(
        STATUS_LIST_CACHE_TTL_MS,
      );
    });

    it('answers revocation lookups from the list', async () => {
      await expect(service.isRevoked(3)).resolves.toBe(true);
      await expect(service.isRevoked(5)).resolves.toBe(false);
    });
  });

  describe('cache', () => {
    it('rebuilds at most once per cache period', async () => {
      await service.getCredential();
      await service.getCredential();

      expect(queryBuilder.getRawMany).toHaveBeenCalledTimes(1);
    });

    it('rebuilds once the cache period is over', async () => {
      jest.useFakeTimers({ now: Date.now() });
      await service.getCredential();
      jest.advanceTimersByTime(STATUS_LIST_CACHE_TTL_MS + 1);

      await service.getCredential();

      expect(queryBuilder.getRawMany).toHaveBeenCalledTimes(2);
    });

    it('rebuilds right after a revocation invalidated it', async () => {
      await service.getCredential();
      queryBuilder.getRawMany.mockResolvedValue([{ index: '9' }]);

      service.invalidate();

      await expect(service.isRevoked(9)).resolves.toBe(true);
      expect(queryBuilder.getRawMany).toHaveBeenCalledTimes(2);
    });
  });
});
