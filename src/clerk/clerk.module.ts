import { Module } from '@nestjs/common';
import { clerkClient } from '@clerk/clerk-sdk-node';
import { ClerkEmailsService } from './clerk-emails.service';
import { CLERK_USERS } from './clerk-users.port';

/** Access to Clerk's user directory behind a port, so services and tests never touch the SDK. */
@Module({
  providers: [
    { provide: CLERK_USERS, useValue: clerkClient.users },
    ClerkEmailsService,
  ],
  exports: [CLERK_USERS, ClerkEmailsService],
})
export class ClerkModule {}
