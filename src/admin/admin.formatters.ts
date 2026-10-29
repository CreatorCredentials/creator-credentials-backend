import { findVerifiedEmail } from 'src/users/verified-email';
import { AdminUser, UserWithCounts } from './admin.types';

/** Expects the SUCCESS EMAIL credential in `user.credentials` and both relation counts mapped. */
export function formatAdminUser(user: UserWithCounts): AdminUser {
  return {
    id: user.id,
    role: user.clerkRole,
    name: user.name ?? null,
    email: findVerifiedEmail(user) ?? null,
    didKey: user.didKey,
    domain: user.domain ?? null,
    didWeb: user.didWeb ?? null,
    organizationName: user.organizationName ?? null,
    createdAt: user.createdAt,
    counts: {
      credentials: user.credentialCount ?? 0,
      issuedCredentials: user.issuedCredentialCount ?? 0,
    },
  };
}

/** `[{ key, count }]` rows of a GROUP BY query as `{ [key]: count }`. */
export function countsByKey(
  rows: { key: string; count: string | number }[],
): Record<string, number> {
  return Object.fromEntries(rows.map((row) => [row.key, Number(row.count)]));
}
