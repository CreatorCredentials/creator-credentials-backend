import { generateKeyPairSync } from 'crypto';
import { of } from 'rxjs';
import { HttpService } from '@nestjs/axios';
import { JwtService } from '@nestjs/jwt';
import { ClerkRole, User } from 'src/users/user.entity';
import { UsersService } from 'src/users/users.service';
import { KeypairChallengeService } from 'src/keypair-challenge/keypair-challenge.service';
import { ClerkEmailsService } from 'src/clerk/clerk-emails.service';
import { CredentialType } from 'src/shared/typings/CredentialType';
import { CredentialVerificationStatus } from 'src/shared/typings/CredentialVerificationStatus';
import { Credential } from './credential.entity';
import { CredentialsController } from './credentials.controller';
import { CredentialsService } from './credentials.service';

const LICCIUM_DID_KEY = 'did:key:zLiccium';
const CLERK_ID = 'clerk_20';

const creator = Object.assign(new User(), {
  id: 20,
  clerkId: CLERK_ID,
  clerkRole: ClerkRole.Creator,
  didKey: 'did:key:zAlice',
});

function buildCredential(overrides: Partial<Credential>): Credential {
  return Object.assign(new Credential(), {
    userId: creator.id,
    credentialStatus: CredentialVerificationStatus.Success,
    credentialObject: {},
    token: 'jwt',
    email: 'x',
    value: 'x',
    ...overrides,
  });
}

const credentialsByType: Partial<Record<CredentialType, Credential[]>> = {
  [CredentialType.EMail]: [
    buildCredential({
      id: 1,
      credentialType: CredentialType.EMail,
      email: 'alice@example.org',
    }),
  ],
  [CredentialType.Member]: [
    buildCredential({ id: 2, credentialType: CredentialType.Member }),
    buildCredential({
      id: 3,
      credentialType: CredentialType.Member,
      credentialStatus: CredentialVerificationStatus.Revoked,
      revokedAt: new Date('2026-02-01T00:00:00.000Z'),
    }),
  ],
  [CredentialType.Creator]: [
    buildCredential({
      id: 4,
      credentialType: CredentialType.Creator,
      email: 'liccium.com',
      value: 'liccium.com',
    }),
  ],
};

describe('CredentialsController export', () => {
  const credentialsService = {
    removeConnectCredential: jest.fn(),
    createConnectCredential: jest.fn(),
    ensureCreatorCredential: jest.fn(),
    getCredentialsOfUserByType: jest.fn(),
  };
  const usersService = { getByClerkId: jest.fn() };
  const httpService = { get: jest.fn() };
  const jwtService = { verify: jest.fn() };
  let controller: CredentialsController;

  beforeAll(() => {
    const { publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
    const jwk = publicKey.export({ format: 'jwk' }) as { n: string; e: string };
    process.env.LICCIUM_CLERK_KEYS_KID = 'kid';
    process.env.LICCIUM_CLERK_KEYS_N = jwk.n;
    process.env.LICCIUM_CLERK_KEYS_E = jwk.e;
  });

  beforeEach(() => {
    jest.resetAllMocks();
    jwtService.verify.mockReturnValue({
      sub: CLERK_ID,
      email: 'alice@example.org',
      licciumDidKey: LICCIUM_DID_KEY,
    });
    httpService.get.mockReturnValue(of({ data: [{ id: CLERK_ID }] }));
    usersService.getByClerkId.mockResolvedValue(creator);
    credentialsService.getCredentialsOfUserByType.mockImplementation(
      async (_user: User, type: CredentialType) =>
        credentialsByType[type] ?? [],
    );

    controller = new CredentialsController(
      credentialsService as unknown as CredentialsService,
      usersService as unknown as UsersService,
      httpService as unknown as HttpService,
      jwtService as unknown as JwtService,
      {} as KeypairChallengeService,
      {} as ClerkEmailsService,
    );
  });

  it('re-issues the Connect credential and ensures one Creator credential', async () => {
    const result = await controller.exportCredentialsForUser('token');

    expect(credentialsService.createConnectCredential).toHaveBeenCalledWith(
      { didKey: creator.didKey, licciumDidKey: LICCIUM_DID_KEY },
      creator,
    );
    expect(credentialsService.ensureCreatorCredential).toHaveBeenCalledTimes(1);
    expect(credentialsService.ensureCreatorCredential).toHaveBeenCalledWith(
      creator,
    );
    expect(result.credentials.verifiableCreator).toMatchObject({
      id: '4',
      type: CredentialType.Creator,
      data: { verifiedBy: 'liccium.com' },
    });
  });

  it('exports SUCCESS credentials only', async () => {
    const result = await controller.exportCredentialsForUser('token');

    expect(result.credentials.membership.map((c) => c.id)).toEqual(['2']);
    expect(result.credentials.email).toMatchObject({ id: '1' });
  });
});
