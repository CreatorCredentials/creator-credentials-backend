export const CLERK_USERS = 'CLERK_USERS';

export type ClerkEmailAddress = {
  id: string;
  emailAddress: string;
};

export type ClerkUser = {
  primaryEmailAddressId: string | null;
  emailAddresses: ClerkEmailAddress[];
};

/** The slice of the Clerk users API notifications need; `clerkClient.users` satisfies it. */
export interface ClerkUsersPort {
  getUser(clerkId: string): Promise<ClerkUser>;
}
