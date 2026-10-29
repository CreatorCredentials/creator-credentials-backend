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

  it('does not emit when the user already exists', async () => {
    usersService.findOrCreate.mockResolvedValue({
      user: storedUser,
      created: false,
    });

    await service.handleEvent({ type: 'user.created', data: signUpData });

    expect(eventEmitter.emit).not.toHaveBeenCalled();
  });

  it('does not emit from the user.updated fallback that creates a user', async () => {
    usersService.getByClerkId.mockResolvedValue(null);
    usersService.create.mockResolvedValue(storedUser);

    await service.handleEvent({ type: 'user.updated', data: signUpData });

    expect(usersService.create).toHaveBeenCalledTimes(1);
    expect(eventEmitter.emit).not.toHaveBeenCalled();
  });
});
