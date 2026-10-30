import { Inject, Injectable, Logger } from '@nestjs/common';
import {
  CLERK_USERS,
  ClerkUsersPort,
  primaryEmailOf,
} from './clerk-users.port';

/** Clerk accepts up to 500 ids per list call; smaller batches keep responses quick. */
const LOOKUP_BATCH_SIZE = 100;

/** Resolves the sign-in e-mail of users from Clerk, the source of truth for addresses shown to issuers. */
@Injectable()
export class ClerkEmailsService {
  private readonly logger = new Logger(ClerkEmailsService.name);

  constructor(
    @Inject(CLERK_USERS) private readonly clerkUsers: ClerkUsersPort,
  ) {}

  /**
   * Primary e-mail per Clerk user id. Ids Clerk does not know, and every id
   * of a batch whose lookup failed, are absent from the result; callers fall
   * back to what the application stores.
   */
  async primaryEmailsByClerkId(
    clerkIds: readonly string[],
  ): Promise<Map<string, string>> {
    const emails = new Map<string, string>();
    const uniqueIds = Array.from(new Set(clerkIds.filter(Boolean)));

    for (let start = 0; start < uniqueIds.length; start += LOOKUP_BATCH_SIZE) {
      const batch = uniqueIds.slice(start, start + LOOKUP_BATCH_SIZE);
      try {
        const { data } = await this.clerkUsers.getUserList({
          userId: batch,
          limit: batch.length,
        });
        for (const user of data) {
          const email = primaryEmailOf(user);
          if (email) emails.set(user.id, email);
        }
      } catch (error) {
        this.logger.warn(
          `Clerk lookup failed for ${batch.length} users: ${error.message}`,
        );
      }
    }
    return emails;
  }
}
