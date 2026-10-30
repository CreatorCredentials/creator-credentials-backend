import { HttpService } from '@nestjs/axios';
import { JwtService } from '@nestjs/jwt';
import { ClerkEmailsService } from 'src/clerk/clerk-emails.service';
import { KeypairChallengeService } from 'src/keypair-challenge/keypair-challenge.service';
import { CredentialType } from 'src/shared/typings/CredentialType';
import { CredentialVerificationStatus } from 'src/shared/typings/CredentialVerificationStatus';
import { ClerkRole, User } from 'src/users/user.entity';
import { UsersService } from 'src/users/users.service';
import { Credential } from './credential.entity';
import { CredentialsController } from './credentials.controller';
import { CredentialsService } from './credentials.service';

function buildUser(overrides: Partial<User>): User {
  return Object.assign(new User(), { credentials: [], ...overrides });
}

const issuer = buildUser({ id: 10, clerkRole: ClerkRole.Issuer });

function issuedMemberCredential(id: number, creator: User): Credential {
  return Object.assign(new Credential(), {
    id,
    issuerId: issuer.id,
    userId: creator.id,
    user: creator,
    credentialType: CredentialType.Member,
    credentialStatus: CredentialVerificationStatus.Success,
    credentialObject: {},
    token: 'jwt',
    value: 'member',
    createdAt: new Date('2026-10-01T00:00:00Z'),
    updatedAt: new Date('2026-10-01T00:00:00Z'),
  });
}

function emailCredential(address: string): Credential {
  return Object.assign(new Credential(), {
    credentialType: CredentialType.EMail,
    credentialStatus: CredentialVerificationStatus.Success,
    email: address,
  });
}

describe('GET credentials/issuers', () => {
  const credentialsService = {
    getAllIssuersMemberCredentialsWithCreators: jest.fn(),
  };
  const clerkEmails = { primaryEmailsByClerkId: jest.fn() };
  const controller = new CredentialsController(
    credentialsService as unknown as CredentialsService,
    {} as UsersService,
    {} as HttpService,
    {} as JwtService,
    {} as KeypairChallengeService,
    clerkEmails as unknown as ClerkEmailsService,
  );

  beforeEach(() => jest.resetAllMocks());

  it('shows the creator e-mail from Clerk and falls back to the EMAIL credential', async () => {
    const alice = buildUser({
      id: 20,
      clerkId: 'clerk_alice',
      credentials: [emailCredential('alice-old@example.org')],
    });
    const bob = buildUser({
      id: 21,
      clerkId: 'clerk_bob',
      credentials: [emailCredential('bob@example.org')],
    });
    credentialsService.getAllIssuersMemberCredentialsWithCreators.mockResolvedValue(
      [issuedMemberCredential(1, alice), issuedMemberCredential(2, bob)],
    );
    clerkEmails.primaryEmailsByClerkId.mockResolvedValue(
      new Map([['clerk_alice', 'alice@example.org']]),
    );

    const { credentials } = await controller.getIssuers(
      issuer,
      CredentialVerificationStatus.Success,
    );

    expect(credentials.map((credential) => credential.creator.email)).toEqual([
      'alice@example.org',
      'bob@example.org',
    ]);
    expect(clerkEmails.primaryEmailsByClerkId).toHaveBeenCalledWith([
      'clerk_alice',
      'clerk_bob',
    ]);
    expect(
      credentialsService.getAllIssuersMemberCredentialsWithCreators,
    ).toHaveBeenCalledWith(issuer.id, CredentialVerificationStatus.Success);
  });
});
