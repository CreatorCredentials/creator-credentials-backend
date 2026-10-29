import { Inject, Injectable, Logger } from '@nestjs/common';
import { OnEvent } from '@nestjs/event-emitter';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { ClerkRole, User } from 'src/users/user.entity';
import { resolveAppBaseUrl } from 'src/shared/app-base-url';
import { MAILER, MailContent, MailerPort } from './mailer.port';
import {
  ConnectionRequestedEvent,
  CredentialRequestedEvent,
  CredentialRevokedEvent,
  NotificationEvent,
  NotificationEventName,
  UserCreatedEvent,
} from './notification-events';
import { RecipientsService } from './recipients.service';
import { connectionRequestedMail } from './templates/connection-requested.mail';
import { credentialRequestedMail } from './templates/credential-requested.mail';
import { credentialRevokedMail } from './templates/credential-revoked.mail';
import { issuedCredentialRevokedMail } from './templates/issued-credential-revoked.mail';
import { userCreatedMail } from './templates/user-created.mail';

export { DEFAULT_APP_BASE_URL } from 'src/shared/app-base-url';

type AddressedMail = MailContent & { to: string[] };

/**
 * Turns domain events into e-mails. Every handler runs after the request
 * that emitted the event and never fails or slows it down: a missing
 * recipient skips the message, any other failure is logged.
 */
@Injectable()
export class NotificationsService {
  private readonly logger = new Logger(NotificationsService.name);
  private readonly appBaseUrl: string;

  constructor(
    @Inject(MAILER) private readonly mailer: MailerPort,
    private readonly recipients: RecipientsService,
    @InjectRepository(User)
    private readonly usersRepository: Repository<User>,
  ) {
    this.appBaseUrl = resolveAppBaseUrl((message) => this.logger.warn(message));
  }

  @OnEvent(NotificationEvent.UserCreated, { async: true })
  async onUserCreated(event: UserCreatedEvent): Promise<void> {
    await this.deliver(NotificationEvent.UserCreated, event, async () => ({
      to: this.recipients.operatorEmails(),
      ...userCreatedMail(event, this.appBaseUrl),
    }));
  }

  @OnEvent(NotificationEvent.ConnectionRequested, { async: true })
  async onConnectionRequested(event: ConnectionRequestedEvent): Promise<void> {
    await this.deliver(
      NotificationEvent.ConnectionRequested,
      event,
      async () => {
        const [issuer, creator] = await this.loadUsers(
          event.issuerId,
          event.creatorId,
        );
        return {
          to: await this.recipientList(issuer),
          ...connectionRequestedMail(
            { creatorName: creator.name },
            this.appBaseUrl,
          ),
        };
      },
    );
  }

  @OnEvent(NotificationEvent.CredentialRequested, { async: true })
  async onCredentialRequested(event: CredentialRequestedEvent): Promise<void> {
    await this.deliver(
      NotificationEvent.CredentialRequested,
      event,
      async () => {
        const [issuer, creator] = await this.loadUsers(
          event.issuerId,
          event.creatorId,
        );
        return {
          to: await this.recipientList(issuer),
          ...credentialRequestedMail(
            { creatorName: creator.name, credentialType: event.credentialType },
            this.appBaseUrl,
          ),
        };
      },
    );
  }

  /**
   * The creator always hears about a revocation. When the platform revoked
   * (admin), the issuer of the credential is told as well; a self-issued
   * credential has no issuer to tell.
   */
  @OnEvent(NotificationEvent.CredentialRevoked, { async: true })
  async onCredentialRevoked(event: CredentialRevokedEvent): Promise<void> {
    const revokedByPlatform = event.revokedByRole === ClerkRole.Admin;

    await this.deliver(NotificationEvent.CredentialRevoked, event, async () => {
      const [creator, issuer] = await Promise.all([
        this.loadUser(event.creatorId),
        this.loadOptionalUser(event.issuerId),
      ]);
      return {
        to: await this.recipientList(creator),
        ...credentialRevokedMail(
          {
            issuerName: issuer?.name ?? null,
            credentialType: event.credentialType,
            reason: event.reason,
            revokedByPlatform,
          },
          this.appBaseUrl,
        ),
      };
    });

    if (!revokedByPlatform || !event.issuerId) {
      return;
    }
    await this.deliver(NotificationEvent.CredentialRevoked, event, async () => {
      const [issuer, creator] = await this.loadUsers(
        event.issuerId,
        event.creatorId,
      );
      return {
        to: await this.recipientList(issuer),
        ...issuedCredentialRevokedMail(
          {
            creatorName: creator.name,
            credentialType: event.credentialType,
            reason: event.reason,
          },
          this.appBaseUrl,
        ),
      };
    });
  }

  private async deliver(
    eventName: NotificationEventName,
    ids: object,
    compose: () => Promise<AddressedMail>,
  ): Promise<void> {
    const context = `${eventName} ${JSON.stringify(ids)}`;
    try {
      const message = await compose();
      if (!message.to.length) {
        this.logger.warn(`${context}: no recipient, message skipped`);
        return;
      }
      await this.mailer.send(message);
    } catch (error) {
      this.logger.error(`${context}: notification failed: ${error.message}`);
    }
  }

  private async loadUsers(...ids: number[]): Promise<User[]> {
    return Promise.all(ids.map((id) => this.loadUser(id)));
  }

  private async loadUser(id: number): Promise<User> {
    const user = await this.usersRepository.findOne({ where: { id } });
    if (!user) {
      throw new Error(`user ${id} not found`);
    }
    return user;
  }

  private async loadOptionalUser(id: number | null): Promise<User | undefined> {
    return id ? this.loadUser(id) : undefined;
  }

  private async recipientList(user: User): Promise<string[]> {
    const email = await this.recipients.emailOf(user);
    return email ? [email] : [];
  }
}
