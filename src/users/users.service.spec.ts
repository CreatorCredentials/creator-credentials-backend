import { Test, TestingModule } from '@nestjs/testing';
import { getRepositoryToken } from '@nestjs/typeorm';
import { ConfigService } from '@nestjs/config';
import { HttpService } from '@nestjs/axios';
import { EventEmitter2 } from '@nestjs/event-emitter';
import { NotFoundException } from '@nestjs/common';
import { ClerkRole, User } from './user.entity';
import { UsersService } from './users.service';
import { Connection } from 'src/connections/connection.entity';
import { ConnectionsService } from 'src/connections/connections.service';
import { CredentialsService } from 'src/credentials/credentials.service';
import { CertificatesService } from 'src/certificates/certificates.service';

function buildUser(overrides: Partial<User>): User {
  return Object.assign(new User(), overrides);
}

const existingUser = buildUser({
  id: 1,
  clerkId: 'clerk_1',
  clerkRole: ClerkRole.Creator,
  nonce: '123',
  nonceChangedAt: new Date('2026-01-01T00:00:00Z'),
});

describe('UsersService', () => {
  const userRepository = {
    findOne: jest.fn(),
    findOneBy: jest.fn(),
    save: jest.fn(),
  };
  const credentialsService = { createEmailCredential: jest.fn() };
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
        { provide: ConnectionsService, useValue: {} },
        { provide: CertificatesService, useValue: {} },
        { provide: EventEmitter2, useValue: { emit: jest.fn() } },
      ],
    }).compile();

    service = module.get(UsersService);
  });

  describe('create', () => {
    it('returns the existing user for a known clerkId without saving', async () => {
      userRepository.findOne.mockResolvedValue(existingUser);

      await expect(
        service.create({
          clerkId: existingUser.clerkId,
          clerkRole: ClerkRole.Creator,
          email: 'alice@example.org',
        }),
      ).resolves.toBe(existingUser);

      expect(userRepository.save).not.toHaveBeenCalled();
      expect(credentialsService.createEmailCredential).not.toHaveBeenCalled();
    });

    it('stores a new user with a nonce and issues the email credential', async () => {
      userRepository.findOne.mockResolvedValue(null);
      userRepository.save.mockImplementation(async (user: User) => user);
      jest.spyOn(service, 'generateCertAndDidKey').mockResolvedValue({
        certificateBuffer: Buffer.from('cert'),
        privateKeyBuffer: Buffer.from('key'),
        didKey: 'did:key:zNew',
      });

      const user = await service.create({
        clerkId: 'clerk_2',
        clerkRole: ClerkRole.Issuer,
        email: 'bob@example.org',
        name: '  Bob  ',
      });

      expect(user).toMatchObject({
        clerkId: 'clerk_2',
        clerkRole: ClerkRole.Issuer,
        name: 'Bob',
        didKey: 'did:key:zNew',
      });
      expect(user.nonce).toMatch(/^\d+$/);
      expect(credentialsService.createEmailCredential).toHaveBeenCalledWith(
        { email: 'bob@example.org', did: 'did:key:zNew' },
        user,
      );
    });
  });

  describe('provideNonceForUser', () => {
    it('rejects an unknown clerkId', async () => {
      userRepository.findOneBy.mockResolvedValue(null);

      await expect(
        service.provideNonceForUser('clerk_missing'),
      ).rejects.toThrow(NotFoundException);
      expect(userRepository.save).not.toHaveBeenCalled();
    });

    it('rotates and returns a fresh nonce for a known user', async () => {
      const user = buildUser({ ...existingUser });
      userRepository.findOneBy.mockResolvedValue(user);
      userRepository.save.mockImplementation(async (saved: User) => saved);

      const result = await service.provideNonceForUser(user.clerkId);

      expect(result.nonce).toMatch(/^\d+$/);
      expect(result.nonce).not.toBe(existingUser.nonce);
      expect(user.nonceChangedAt.getTime()).toBeGreaterThan(
        existingUser.nonceChangedAt.getTime(),
      );
      expect(userRepository.save).toHaveBeenCalledWith(user);
    });
  });
});
