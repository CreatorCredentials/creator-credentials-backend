import { Inject, Injectable, Logger } from '@nestjs/common';
import { OnEvent } from '@nestjs/event-emitter';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { User } from 'src/users/user.entity';
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
import { userCreatedMail } from './templates/user-created.mail';

type AddressedMail = MailContent & { to: string[] };

/** Origin the mail links point at when APP_BASE_URL is not configured. */
export const DEFAULT_APP_BASE_URL = 'https://creatorcredentials.app';

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
    this.appBaseUrl = this.resolveAppBaseUrl();
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

  @OnEvent(NotificationEvent.CredentialRevoked, { async: true })
  async onCredentialRevoked(event: CredentialRevokedEvent): Promise<void> {
    await this.deliver(NotificationEvent.CredentialRevoked, event, async () => {
      const [issuer, creator] = await this.loadUsers(
        event.issuerId,
        event.creatorId,
      );
      return {
        to: await this.recipientList(creator),
        ...credentialRevokedMail(
          {
            issuerName: issuer.name,
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
    return Promise.all(
      ids.map(async (id) => {
        const user = await this.usersRepository.findOne({ where: { id } });
        if (!user) {
          throw new Error(`user ${id} not found`);
        }
        return user;
      }),
    );
  }

  private async recipientList(user: User): Promise<string[]> {
    const email = await this.recipients.emailOf(user);
    return email ? [email] : [];
  }

  private resolveAppBaseUrl(): string {
    const configured = process.env.APP_BASE_URL?.trim();
    if (configured) {
      return configured;
    }
    this.logger.warn(
      `APP_BASE_URL is not set, notification links use ${DEFAULT_APP_BASE_URL}`,
    );
    return DEFAULT_APP_BASE_URL;
  }
}
