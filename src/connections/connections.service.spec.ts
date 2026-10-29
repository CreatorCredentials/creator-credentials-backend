import { Test, TestingModule } from '@nestjs/testing';
import { getRepositoryToken } from '@nestjs/typeorm';
import { ClerkRole, User } from 'src/users/user.entity';
import { Connection, ConnectionStatus } from './connection.entity';
import { ConnectionsService } from './connections.service';

function buildUser(overrides: Partial<User>): User {
  return Object.assign(new User(), overrides);
}

const issuer = buildUser({ id: 10, clerkRole: ClerkRole.Issuer });
const creator = buildUser({ id: 20, clerkRole: ClerkRole.Creator });

describe('ConnectionsService', () => {
  const connectionRepository = { findOne: jest.fn(), save: jest.fn() };
  let service: ConnectionsService;

  beforeEach(async () => {
    jest.resetAllMocks();

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        ConnectionsService,
        {
          provide: getRepositoryToken(Connection),
          useValue: connectionRepository,
        },
      ],
    }).compile();

    service = module.get(ConnectionsService);
  });

  describe('createConnection', () => {
    it('stores a new issuer–creator connection', async () => {
      connectionRepository.findOne.mockResolvedValue(null);
      connectionRepository.save.mockImplementation(
        async (connection: Connection) => connection,
      );

      const connection = await service.createConnection([creator, issuer]);

      expect(connection.issuer).toBe(issuer);
      expect(connection.creator).toBe(creator);
      expect(connectionRepository.findOne).toHaveBeenCalledWith({
        where: [
          {
            issuerId: issuer.id,
            creatorId: creator.id,
            status: ConnectionStatus.Requested,
          },
          {
            issuerId: issuer.id,
            creatorId: creator.id,
            status: ConnectionStatus.Accepted,
          },
        ],
      });
    });

    it('refuses a second connection while one is pending or accepted', async () => {
      connectionRepository.findOne.mockResolvedValue(new Connection());

      await expect(service.createConnection([issuer, creator])).rejects.toThrow(
        /already exists/,
      );
      expect(connectionRepository.save).not.toHaveBeenCalled();
    });

    it('requires exactly one issuer and one creator', async () => {
      await expect(service.createConnection([issuer])).rejects.toThrow(
        /two users/,
      );
      await expect(service.createConnection([issuer, issuer])).rejects.toThrow(
        /Issuer and Creator/,
      );
      expect(connectionRepository.findOne).not.toHaveBeenCalled();
    });
  });
});
