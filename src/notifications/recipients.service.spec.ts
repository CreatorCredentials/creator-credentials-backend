import { ClerkRole, User } from 'src/users/user.entity';
import { Credential } from 'src/credentials/credential.entity';
import { CredentialType } from 'src/shared/typings/CredentialType';
import { CredentialVerificationStatus } from 'src/shared/typings/CredentialVerificationStatus';
import { ClerkUsersPort } from 'src/clerk/clerk-users.port';
import { RecipientsService } from './recipients.service';

const VERIFIED_EMAIL = 'verified@example.org';
const PRIMARY_EMAIL = 'primary@example.org';

function buildUser(credentials: Credential[]): User {
  return Object.assign(new User(), {
    id: 20,
    clerkId: 'clerk_20',
    clerkRole: ClerkRole.Creator,
    credentials,
  });
}

function buildEmailCredential(
  status: CredentialVerificationStatus,
): Credential {
  return Object.assign(new Credential(), {
    credentialType: CredentialType.EMail,
    credentialStatus: status,
    email: VERIFIED_EMAIL,
  });
}

describe('RecipientsService', () => {
  const clerkUsers = { getUser: jest.fn() };
  let service: RecipientsService;

  beforeEach(() => {
    jest.resetAllMocks();
    delete process.env.NOTIFY_ADMIN_EMAILS;
    service = new RecipientsService(clerkUsers as unknown as ClerkUsersPort);
  });

  describe('emailOf', () => {
    it('prefers the primary Clerk e-mail', async () => {
      clerkUsers.getUser.mockResolvedValue({
        primaryEmailAddressId: 'e2',
        emailAddresses: [
          { id: 'e1', emailAddress: 'secondary@example.org' },
          { id: 'e2', emailAddress: PRIMARY_EMAIL },
        ],
      });

      await expect(
        service.emailOf(
          buildUser([
            buildEmailCredential(CredentialVerificationStatus.Success),
          ]),
        ),
      ).resolves.toBe(PRIMARY_EMAIL);
      expect(clerkUsers.getUser).toHaveBeenCalledWith('clerk_20');
    });

    it('falls back to the verified EMAIL credential when Clerk has no address', async () => {
      clerkUsers.getUser.mockResolvedValue({
        primaryEmailAddressId: null,
        emailAddresses: [],
      });

      await expect(
        service.emailOf(
          buildUser([
            buildEmailCredential(CredentialVerificationStatus.Success),
          ]),
        ),
      ).resolves.toBe(VERIFIED_EMAIL);
    });

    it('falls back to the verified EMAIL credential when Clerk fails', async () => {
      clerkUsers.getUser.mockRejectedValue(new Error('Clerk unavailable'));

      await expect(
        service.emailOf(
          buildUser([
            buildEmailCredential(CredentialVerificationStatus.Success),
          ]),
        ),
      ).resolves.toBe(VERIFIED_EMAIL);
    });

    it('resolves nothing when neither source has an address', async () => {
      clerkUsers.getUser.mockRejectedValue(new Error('Clerk unavailable'));

      await expect(
        service.emailOf(
          buildUser([
            buildEmailCredential(CredentialVerificationStatus.Pending),
          ]),
        ),
      ).resolves.toBeUndefined();
    });
  });

  describe('operatorEmails', () => {
    it('is empty when NOTIFY_ADMIN_EMAILS is not set', () => {
      expect(service.operatorEmails()).toEqual([]);
    });

    it('splits NOTIFY_ADMIN_EMAILS on commas and trims the entries', () => {
      process.env.NOTIFY_ADMIN_EMAILS = ' ops@example.org, admin@example.org ,';

      expect(service.operatorEmails()).toEqual([
        'ops@example.org',
        'admin@example.org',
      ]);
    });
  });
});
