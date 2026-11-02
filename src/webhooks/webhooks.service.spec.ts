import { EventEmitter2 } from '@nestjs/event-emitter';
import { ClerkRole } from '../users/user.entity';
import { UsersService } from '../users/users.service';
import { NotificationEvent } from 'src/notifications/notification-events';
import { WebhooksService } from './webhooks.service';

const CLERK_ID = 'clerk_1';
const EMAIL = 'alice@example.org';

const signUpData = {
  id: CLERK_ID,
  primary_email_address_id: 'e1',
  email_addresses: [{ id: 'e1', email_address: EMAIL }],
  public_metadata: {
    role: 'CREATOR',
    name: 'Alice',
    termsAreAccepted: true,
    termsLink: 'https://example.org/terms',
  },
};

const storedUser = { id: 20, clerkRole: ClerkRole.Creator, name: 'Alice' };

describe('WebhooksService', () => {
  const usersService = {
    findOrCreate: jest.fn(),
    create: jest.fn(),
    getByClerkId: jest.fn(),
    updateClerkProfile: jest.fn(),
  };
  const eventEmitter = { emit: jest.fn() };
  let service: WebhooksService;

  beforeEach(() => {
    jest.resetAllMocks();
    service = new WebhooksService(
      usersService as unknown as UsersService,
      eventEmitter as unknown as EventEmitter2,
    );
  });

  it('emits user.created once for a newly created user', async () => {
    usersService.findOrCreate.mockResolvedValue({
      user: storedUser,
      created: true,
    });

    await service.handleEvent({ type: 'user.created', data: signUpData });

    expect(usersService.findOrCreate).toHaveBeenCalledWith(
      expect.objectContaining({ clerkId: CLERK_ID, email: EMAIL }),
    );
    expect(eventEmitter.emit).toHaveBeenCalledTimes(1);
    expect(eventEmitter.emit).toHaveBeenCalledWith(
      NotificationEvent.UserCreated,
      {
        userId: storedUser.id,
        role: ClerkRole.Creator,
        name: 'Alice',
        email: EMAIL,
      },
    );
  });

  it('maps the ADMIN metadata role to the admin role', async () => {
    usersService.findOrCreate.mockResolvedValue({
      user: { ...storedUser, clerkRole: ClerkRole.Admin },
      created: true,
    });

    await service.handleEvent({
      type: 'user.created',
      data: {
        ...signUpData,
        public_metadata: { ...signUpData.public_metadata, role: 'ADMIN' },
      },
    });

    expect(usersService.findOrCreate).toHaveBeenCalledWith(
      expect.objectContaining({ clerkRole: ClerkRole.Admin }),
    );
  });

  describe('admins created by operators in the Clerk dashboard', () => {
    const adminData = {
      id: CLERK_ID,
      primary_email_address_id: 'e1',
      email_addresses: [{ id: 'e1', email_address: EMAIL }],
      public_metadata: { role: 'ADMIN', name: 'Ops' },
    };

    it('creates the row on user.created although no terms were accepted', async () => {
      usersService.findOrCreate.mockResolvedValue({
        user: { id: 21, clerkRole: ClerkRole.Admin, name: 'Ops' },
        created: true,
      });

      await service.handleEvent({ type: 'user.created', data: adminData });

      expect(usersService.findOrCreate).toHaveBeenCalledWith(
        expect.objectContaining({
          clerkId: CLERK_ID,
          clerkRole: ClerkRole.Admin,
          termsLink: undefined,
        }),
      );
    });

    it('creates the row on user.updated when the account is not known yet', async () => {
      usersService.getByClerkId.mockResolvedValue(null);

      usersService.findOrCreate.mockResolvedValue({
        user: { id: 21, clerkRole: ClerkRole.Admin, name: 'Ops' },
        created: true,
      });

      await service.handleEvent({ type: 'user.updated', data: adminData });

      expect(usersService.findOrCreate).toHaveBeenCalledWith(
        expect.objectContaining({
          clerkId: CLERK_ID,
          clerkRole: ClerkRole.Admin,
          email: EMAIL,
        }),
      );
    });

    it('still waits for the terms of an issuer or creator', async () => {
      const creatorWithoutTerms = {
        ...adminData,
        public_metadata: { role: 'CREATOR', name: 'Alice' },
      };
      usersService.getByClerkId.mockResolvedValue(null);

      await service.handleEvent({
        type: 'user.created',
        data: creatorWithoutTerms,
      });
      await service.handleEvent({
        type: 'user.updated',
        data: creatorWithoutTerms,
      });

      expect(usersService.findOrCreate).not.toHaveBeenCalled();
    });

    it('does not create a row for an admin claimed only in unsafe metadata', async () => {
      usersService.getByClerkId.mockResolvedValue(null);

      await service.handleEvent({
        type: 'user.created',
        data: {
          ...adminData,
          public_metadata: {},
          unsafe_metadata: { role: 'ADMIN' },
        },
      });

      expect(usersService.findOrCreate).not.toHaveBeenCalled();
    });
  });

  it('never grants the admin role from the browser-writable unsafe metadata', async () => {
    usersService.findOrCreate.mockResolvedValue({
      user: storedUser,
      created: true,
    });

    await service.handleEvent({
      type: 'user.created',
      data: {
        ...signUpData,
        public_metadata: { ...signUpData.public_metadata, role: undefined },
        unsafe_metadata: { role: 'ADMIN' },
      },
    });

    expect(usersService.findOrCreate).toHaveBeenCalledWith(
      expect.objectContaining({ clerkRole: ClerkRole.Creator }),
    );
  });

  it('does not emit when the user already exists', async () => {
    usersService.findOrCreate.mockResolvedValue({
      user: storedUser,
      created: false,
    });

    await service.handleEvent({ type: 'user.created', data: signUpData });

    expect(eventEmitter.emit).not.toHaveBeenCalled();
  });

  it('announces the sign-up when user.updated is the event that creates the row', async () => {
    usersService.getByClerkId.mockResolvedValue(null);
    usersService.findOrCreate.mockResolvedValue({
      user: storedUser,
      created: true,
    });

    await service.handleEvent({ type: 'user.updated', data: signUpData });

    expect(usersService.findOrCreate).toHaveBeenCalledTimes(1);
    expect(eventEmitter.emit).toHaveBeenCalledTimes(1);
    expect(eventEmitter.emit).toHaveBeenCalledWith(
      NotificationEvent.UserCreated,
      expect.objectContaining({ userId: storedUser.id, email: EMAIL }),
    );
  });

  it('does not announce twice when user.updated finds the row already created', async () => {
    usersService.getByClerkId.mockResolvedValue(null);
    usersService.findOrCreate.mockResolvedValue({
      user: storedUser,
      created: false,
    });

    await service.handleEvent({ type: 'user.updated', data: signUpData });

    expect(eventEmitter.emit).not.toHaveBeenCalled();
  });
});
