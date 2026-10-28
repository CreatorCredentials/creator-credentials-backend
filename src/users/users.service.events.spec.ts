import { Test, TestingModule } from '@nestjs/testing';
import { getRepositoryToken } from '@nestjs/typeorm';
import { ConfigService } from '@nestjs/config';
import { HttpService } from '@nestjs/axios';
import { EventEmitter2 } from '@nestjs/event-emitter';
import { ClerkRole, User } from './user.entity';
import { UsersService } from './users.service';
import { Connection } from 'src/connections/connection.entity';
import { ConnectionsService } from 'src/connections/connections.service';
import { CredentialsService } from 'src/credentials/credentials.service';
import { CertificatesService } from 'src/certificates/certificates.service';
import { NotificationEvent } from 'src/notifications/notification-events';

function buildUser(overrides: Partial<User>): User {
  return Object.assign(new User(), overrides);
}

const issuer = buildUser({ id: 10, clerkRole: ClerkRole.Issuer });
const creator = buildUser({
  id: 20,
  clerkRole: ClerkRole.Creator,
  clerkId: 'clerk_20',
  didKey: 'did:key:zAlice',
});

describe('UsersService', () => {
  const userRepository = { findOne: jest.fn(), save: jest.fn() };
  const credentialsService = {
    createConnectCredential: jest.fn(),
    ensureCreatorCredential: jest.fn(),
  };
  const connectionsService = { createConnection: jest.fn() };
  const eventEmitter = { emit: jest.fn() };
  let service: UsersService;

  beforeEach(async () => {
    jest.resetAllMocks();

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        UsersService,
        { provide: getRepositoryToken(User), useValue: userRepository },
        { provide: getRepositoryToken(Connection), useValue: {} },
        { provide: CredentialsService, useValue: credentialsService },
        { provide: ConfigService, useValue: {} },
        { provide: HttpService, useValue: {} },
        { provide: ConnectionsService, useValue: connectionsService },
        { provide: CertificatesService, useValue: {} },
        { provide: EventEmitter2, useValue: eventEmitter },
      ],
    }).compile();

    service = module.get(UsersService);
  });

  describe('findOrCreate', () => {
    it('returns the existing user without creating anything', async () => {
      userRepository.findOne.mockResolvedValue(creator);

      await expect(
        service.findOrCreate({
          clerkId: creator.clerkId,
          clerkRole: ClerkRole.Creator,
          email: 'alice@example.org',
        }),
      ).resolves.toEqual({ user: creator, created: false });

      expect(userRepository.save).not.toHaveBeenCalled();
    });
  });

  describe('createConnection', () => {
    it('emits connection.requested after the connection is stored', async () => {
      userRepository.findOne.mockResolvedValue(issuer);
      connectionsService.createConnection.mockResolvedValue({ id: 7 });

      await service.createConnection(issuer.id, creator);

      expect(connectionsService.createConnection).toHaveBeenCalledWith([
        issuer,
        creator,
      ]);
      expect(eventEmitter.emit).toHaveBeenCalledWith(
        NotificationEvent.ConnectionRequested,
        { connectionId: 7, issuerId: issuer.id, creatorId: creator.id },
      );
    });
  });

  describe('connectLicciumDidKeyToUser', () => {
    it('issues the Connect credential and ensures the Creator credential once', async () => {
      const linked = buildUser({
        ...creator,
        licciumDidKey: 'did:key:zLiccium',
      });
      userRepository.save.mockResolvedValue(linked);

      await service.connectLicciumDidKeyToUser(creator, 'did:key:zLiccium');

      expect(credentialsService.createConnectCredential).toHaveBeenCalledWith(
        { didKey: creator.didKey, licciumDidKey: 'did:key:zLiccium' },
        linked,
      );
      expect(credentialsService.ensureCreatorCredential).toHaveBeenCalledTimes(
        1,
      );
      expect(credentialsService.ensureCreatorCredential).toHaveBeenCalledWith(
        linked,
      );
    });
  });
});
