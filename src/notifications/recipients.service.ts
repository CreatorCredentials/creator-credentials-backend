import { Inject, Injectable, Logger } from '@nestjs/common';
import { User } from 'src/users/user.entity';
import { findVerifiedEmail } from 'src/users/verified-email';
import {
  CLERK_USERS,
  ClerkUsersPort,
  primaryEmailOf,
} from 'src/clerk/clerk-users.port';

@Injectable()
export class RecipientsService {
  private readonly logger = new Logger(RecipientsService.name);

  constructor(
    @Inject(CLERK_USERS) private readonly clerkUsers: ClerkUsersPort,
  ) {}

  /** The user's primary Clerk e-mail, falling back to the e-mail verified in the app. */
  async emailOf(user: User): Promise<string | undefined> {
    return (await this.clerkPrimaryEmail(user)) ?? findVerifiedEmail(user);
  }

  /** Operators listed in NOTIFY_ADMIN_EMAILS, comma separated. */
  operatorEmails(): string[] {
    return (process.env.NOTIFY_ADMIN_EMAILS ?? '')
      .split(',')
      .map((address) => address.trim())
      .filter(Boolean);
  }

  private async clerkPrimaryEmail(user: User): Promise<string | undefined> {
    try {
      return primaryEmailOf(await this.clerkUsers.getUser(user.clerkId));
    } catch (error) {
      this.logger.warn(
        `Clerk lookup failed for user ${user.id}: ${error.message}`,
      );
      return undefined;
    }
  }
}
