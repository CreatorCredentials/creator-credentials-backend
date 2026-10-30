import { NotFoundException } from '@nestjs/common';
import { HttpService } from '@nestjs/axios';
import { JwtService } from '@nestjs/jwt';
import { KeypairChallengeService } from 'src/keypair-challenge/keypair-challenge.service';
import { ClerkEmailsService } from 'src/clerk/clerk-emails.service';
import { CredentialType } from 'src/shared/typings/CredentialType';
import { ClerkRole, User } from 'src/users/user.entity';
import { UsersService } from 'src/users/users.service';
import { CredentialsController } from './credentials.controller';
import { CredentialsService } from './credentials.service';

const admin = Object.assign(new User(), {
  id: 30,
  clerkRole: ClerkRole.Admin,
});

/**
 * An admin never requests, accepts, signs, revokes or rejects a credential
 * through the issuer and creator routes: every mutation rejects the role
 * before touching a service.
 */
describe('CredentialsController role checks for an admin', () => {
  const credentialsService = new Proxy({} as CredentialsService, {
    get: () =>
      jest.fn().mockRejectedValue(new Error('service must not be called')),
  });
  const controller = new CredentialsController(
    credentialsService,
    {} as UsersService,
    {} as HttpService,
    {} as JwtService,
    {} as KeypairChallengeService,
    {} as ClerkEmailsService,
  );

  const mutations: [string, () => Promise<unknown>][] = [
    [
      'POST credentials/create/email',
      () =>
        controller.createEmailCredential(
          { email: 'a@example.org', did: 'did:key:zAdmin' },
          admin,
        ),
    ],
    [
      'POST credentials/request',
      () =>
        controller.requestCredentialsFromIssuer(
          admin,
          10,
          CredentialType.Member,
        ),
    ],
    [
      'POST credentials/:id/accept',
      () => controller.acceptCredentialByIssuer(admin, 1),
    ],
    [
      'POST credentials/:id/accept/verify-signature',
      () => controller.verifyAcceptedCredentialByIssuer(admin, 1, 'sig'),
    ],
    [
      'POST credentials/:id/revoke',
      () => controller.revokeCredentialByIssuer(admin, 1, { reason: 'x' }),
    ],
    [
      'POST credentials/:id/reject',
      () => controller.rejectCredentialByIssuer(admin, 1),
    ],
    [
      'DELETE credentials/:id',
      () => controller.deleteMemberCredentialByIssuer(admin, 1),
    ],
  ];

  it.each(mutations)('%s rejects an admin', async (_route, call) => {
    await expect(call()).rejects.toThrow(NotFoundException);
  });
});
