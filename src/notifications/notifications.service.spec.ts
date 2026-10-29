import { Test, TestingModule } from '@nestjs/testing';
import { getRepositoryToken } from '@nestjs/typeorm';
import { ClerkRole, User } from 'src/users/user.entity';
import { CredentialType } from 'src/shared/typings/CredentialType';
import { FakeMailer } from './adapters/fake-mailer';
import { MAILER } from './mailer.port';
import {
  DEFAULT_APP_BASE_URL,
  NotificationsService,
} from './notifications.service';
import { RecipientsService } from './recipients.service';

const APP_BASE_URL = 'https://app.example.org';
const ISSUER_EMAIL = 'issuer@example.org';
const CREATOR_EMAIL = 'alice@example.org';
const OPERATOR_EMAIL = 'ops@example.org';

function buildUser(overrides: Partial<User>): User {
  return Object.assign(new User(), { credentials: [], ...overrides });
}

const issuer = buildUser({
  id: 10,
  clerkRole: ClerkRole.Issuer,
  name: 'Issuer Inc',
});
const creator = buildUser({
  id: 20,
  clerkRole: ClerkRole.Creator,
  name: 'Alice',
});

describe('NotificationsService', () => {
  let mailer: FakeMailer;
  let service: NotificationsService;
  const recipients = {
    emailOf: jest.fn(),
    operatorEmails: jest.fn(),
  };
  const usersRepository = { findOne: jest.fn() };

  beforeEach(async () => {
    process.env.APP_BASE_URL = APP_BASE_URL;
    jest.resetAllMocks();
    recipients.emailOf.mockImplementation(async (user: User) =>
      user.id === issuer.id ? ISSUER_EMAIL : CREATOR_EMAIL,
    );
    recipients.operatorEmails.mockReturnValue([OPERATOR_EMAIL]);
    usersRepository.findOne.mockImplementation(async ({ where }) =>
      [issuer, creator].find((user) => user.id === where.id),
    );
    mailer = new FakeMailer();

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        NotificationsService,
        { provide: MAILER, useValue: mailer },
        { provide: RecipientsService, useValue: recipients },
        { provide: getRepositoryToken(User), useValue: usersRepository },
      ],
    }).compile();

    service = module.get(NotificationsService);
  });

  afterEach(() => {
    delete process.env.APP_BASE_URL;
  });

  it('mails the operators about a sign-up', async () => {
    await service.onUserCreated({
      userId: creator.id,
      role: ClerkRole.Creator,
      name: 'Alice',
      email: CREATOR_EMAIL,
    });

    expect(mailer.messages).toHaveLength(1);
    expect(mailer.messages[0]).toMatchObject({
      to: [OPERATOR_EMAIL],
      subject: 'New sign-up on Creator Credentials: Alice (creator)',
    });
    expect(mailer.messages[0].text).toContain(`${APP_BASE_URL}/`);
  });

  it('mails the issuer about a connection request', async () => {
    await service.onConnectionRequested({
      connectionId: 7,
      issuerId: issuer.id,
      creatorId: creator.id,
    });

    expect(mailer.messages).toHaveLength(1);
    expect(mailer.messages[0]).toMatchObject({
      to: [ISSUER_EMAIL],
      subject: 'New connection request from Alice',
    });
    expect(mailer.messages[0].text).toContain(
      `${APP_BASE_URL}/issuer/creators`,
    );
  });

  it('mails the issuer about a credential request with the type label', async () => {
    await service.onCredentialRequested({
      credentialId: 1,
      issuerId: issuer.id,
      creatorId: creator.id,
      credentialType: CredentialType.Member,
    });

    expect(mailer.messages).toHaveLength(1);
    expect(mailer.messages[0]).toMatchObject({
      to: [ISSUER_EMAIL],
      subject: 'New Member credential request from Alice',
    });
    expect(mailer.messages[0].text).toContain(
      `${APP_BASE_URL}/issuer/credentials/requested`,
    );
  });

  it('mails the creator about a revocation with the reason', async () => {
    await service.onCredentialRevoked({
      credentialId: 1,
      issuerId: issuer.id,
      creatorId: creator.id,
      credentialType: CredentialType.Member,
      reason: 'Membership ended',
      revokedByRole: ClerkRole.Issuer,
    });

    expect(mailer.messages).toHaveLength(1);
    expect(mailer.messages[0]).toMatchObject({
      to: [CREATOR_EMAIL],
      subject: 'Your Member credential was revoked by Issuer Inc',
    });
    expect(mailer.messages[0].text).toContain('Reason: Membership ended');
    expect(mailer.messages[0].text).toContain(
      `${APP_BASE_URL}/creator/credentials`,
    );
    expect(mailer.messages[0].html).toContain('<a href=');
  });

  it('mails the creator and the issuer when the platform revoked', async () => {
    await service.onCredentialRevoked({
      credentialId: 1,
      issuerId: issuer.id,
      creatorId: creator.id,
      credentialType: CredentialType.Member,
      reason: 'Terms violated',
      revokedByRole: ClerkRole.Admin,
    });

    expect(mailer.messages).toHaveLength(2);
    expect(mailer.messages[0]).toMatchObject({
      to: [CREATOR_EMAIL],
      subject:
        'Your Member credential was revoked by the Creator Credentials platform',
    });
    expect(mailer.messages[0].text).toContain('issued by Issuer Inc');
    expect(mailer.messages[1]).toMatchObject({
      to: [ISSUER_EMAIL],
      subject: 'The Member credential you issued to Alice was revoked',
    });
    expect(mailer.messages[1].text).toContain('Reason: Terms violated');
    expect(mailer.messages[1].text).toContain(
      `${APP_BASE_URL}/issuer/credentials`,
    );
  });

  it('tells only the creator when the platform revoked a self-issued credential', async () => {
    await service.onCredentialRevoked({
      credentialId: 1,
      issuerId: null,
      creatorId: creator.id,
      credentialType: CredentialType.EMail,
      reason: null,
      revokedByRole: ClerkRole.Admin,
    });

    expect(mailer.messages).toHaveLength(1);
    expect(mailer.messages[0].to).toEqual([CREATOR_EMAIL]);
    expect(mailer.messages[0].text).toContain(
      'The Creator Credentials platform revoked your E-Mail credential on Creator Credentials.',
    );
  });

  it('skips the message when no recipient can be resolved', async () => {
    recipients.emailOf.mockResolvedValue(undefined);

    await service.onConnectionRequested({
      connectionId: 7,
      issuerId: issuer.id,
      creatorId: creator.id,
    });

    expect(mailer.messages).toHaveLength(0);
  });

  it('links to the default origin when APP_BASE_URL is not configured', async () => {
    delete process.env.APP_BASE_URL;
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        NotificationsService,
        { provide: MAILER, useValue: mailer },
        { provide: RecipientsService, useValue: recipients },
        { provide: getRepositoryToken(User), useValue: usersRepository },
      ],
    }).compile();

    await module.get(NotificationsService).onConnectionRequested({
      connectionId: 7,
      issuerId: issuer.id,
      creatorId: creator.id,
    });

    expect(mailer.messages[0].text).toContain(
      `${DEFAULT_APP_BASE_URL}/issuer/creators`,
    );
  });

  it('never propagates a mailer failure', async () => {
    jest.spyOn(mailer, 'send').mockRejectedValue(new Error('SES down'));

    await expect(
      service.onCredentialRevoked({
        credentialId: 1,
        issuerId: issuer.id,
        creatorId: creator.id,
        credentialType: CredentialType.Member,
        reason: null,
        revokedByRole: ClerkRole.Issuer,
      }),
    ).resolves.toBeUndefined();
  });
});
