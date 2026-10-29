import { NotFoundException } from '@nestjs/common';
import { CredentialsService } from 'src/credentials/credentials.service';
import { ClerkRole, User } from './user.entity';
import { UsersController } from './users.controller';
import { UsersService } from './users.service';

const admin = Object.assign(new User(), {
  id: 30,
  clerkRole: ClerkRole.Admin,
});

/** The connection endpoints belong to issuers and creators; an admin is rejected before any service call. */
describe('UsersController role checks for an admin', () => {
  const usersService = new Proxy({} as UsersService, {
    get: () =>
      jest.fn().mockRejectedValue(new Error('service must not be called')),
  });
  const controller = new UsersController(
    usersService,
    {} as CredentialsService,
  );

  const mutations: [string, () => Promise<unknown>][] = [
    [
      'POST users/creators/:id/accept',
      () => controller.acceptCreatorConnection(admin, 20),
    ],
    [
      'POST users/creators/:id/reject',
      () => controller.rejectCreatorConnection(admin, 20),
    ],
    [
      'POST users/creators/:id/revoke',
      () => controller.revokeCreatorConnection(admin, 20),
    ],
    [
      'POST users/issuers/:id/confirm-request',
      () => controller.confirmIssuerRequest(admin, 10),
    ],
  ];

  it.each(mutations)('%s rejects an admin', async (_route, call) => {
    await expect(call()).rejects.toThrow(NotFoundException);
  });
});
