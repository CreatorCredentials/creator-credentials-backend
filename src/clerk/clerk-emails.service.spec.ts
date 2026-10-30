import { ClerkEmailsService } from './clerk-emails.service';
import { ClerkUser, ClerkUsersPort } from './clerk-users.port';

function clerkUser(id: string, emails: string[], primaryIndex = 0): ClerkUser {
  return {
    id,
    primaryEmailAddressId: emails.length ? `${id}-e${primaryIndex}` : null,
    emailAddresses: emails.map((emailAddress, index) => ({
      id: `${id}-e${index}`,
      emailAddress,
    })),
  };
}

describe('ClerkEmailsService', () => {
  const clerkUsers = { getUser: jest.fn(), getUserList: jest.fn() };
  const service = new ClerkEmailsService(
    clerkUsers as unknown as ClerkUsersPort,
  );

  beforeEach(() => jest.resetAllMocks());

  it('maps each known user to the primary address, deduplicating ids', async () => {
    clerkUsers.getUserList.mockResolvedValue({
      data: [
        clerkUser('c1', ['old@example.org', 'alice@example.org'], 1),
        clerkUser('c2', ['bob@example.org']),
      ],
    });

    const emails = await service.primaryEmailsByClerkId(['c1', 'c2', 'c1']);

    expect(Object.fromEntries(emails)).toEqual({
      c1: 'alice@example.org',
      c2: 'bob@example.org',
    });
    expect(clerkUsers.getUserList).toHaveBeenCalledTimes(1);
    expect(clerkUsers.getUserList).toHaveBeenCalledWith({
      userId: ['c1', 'c2'],
      limit: 2,
    });
  });

  it('leaves out users without an address and ids Clerk does not return', async () => {
    clerkUsers.getUserList.mockResolvedValue({
      data: [clerkUser('c1', [])],
    });

    const emails = await service.primaryEmailsByClerkId(['c1', 'c2']);

    expect(emails.size).toBe(0);
  });

  it('splits large lookups into batches and survives a failed batch', async () => {
    const ids = Array.from({ length: 150 }, (_, index) => `c${index}`);
    clerkUsers.getUserList
      .mockRejectedValueOnce(new Error('rate limited'))
      .mockResolvedValueOnce({
        data: [clerkUser('c149', ['last@example.org'])],
      });

    const emails = await service.primaryEmailsByClerkId(ids);

    expect(clerkUsers.getUserList).toHaveBeenCalledTimes(2);
    expect(clerkUsers.getUserList.mock.calls[0][0].userId).toHaveLength(100);
    expect(clerkUsers.getUserList.mock.calls[1][0].userId).toHaveLength(50);
    expect(Object.fromEntries(emails)).toEqual({ c149: 'last@example.org' });
  });

  it('asks Clerk nothing for an empty list', async () => {
    const emails = await service.primaryEmailsByClerkId([]);

    expect(emails.size).toBe(0);
    expect(clerkUsers.getUserList).not.toHaveBeenCalled();
  });
});
