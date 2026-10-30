export const CLERK_USERS = 'CLERK_USERS';

export type ClerkEmailAddress = {
  id: string;
  emailAddress: string;
};

export type ClerkUser = {
  id: string;
  primaryEmailAddressId: string | null;
  emailAddresses: ClerkEmailAddress[];
};

export type ClerkUserListParams = {
  userId: string[];
  limit?: number;
};

/** The slice of the Clerk users API this application needs; `clerkClient.users` satisfies it. */
export interface ClerkUsersPort {
  getUser(clerkId: string): Promise<ClerkUser>;
  getUserList(params: ClerkUserListParams): Promise<{ data: ClerkUser[] }>;
}

/** The address Clerk marks as primary, else the first one on the account. */
export function primaryEmailOf(user: ClerkUser): string | undefined {
  const primary = user.emailAddresses.find(
    (address) => address.id === user.primaryEmailAddressId,
  );
  return (primary ?? user.emailAddresses[0])?.emailAddress;
}
