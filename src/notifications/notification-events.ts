import { ClerkRole } from 'src/users/user.entity';
import { CredentialType } from 'src/shared/typings/CredentialType';

export const NotificationEvent = {
  UserCreated: 'user.created',
  ConnectionRequested: 'connection.requested',
  CredentialRequested: 'credential.requested',
  CredentialRevoked: 'credential.revoked',
} as const;

export type NotificationEventName =
  (typeof NotificationEvent)[keyof typeof NotificationEvent];

export type UserCreatedEvent = {
  userId: number;
  role: ClerkRole;
  name: string;
  email: string;
};

export type ConnectionRequestedEvent = {
  connectionId: number;
  issuerId: number;
  creatorId: number;
};

export type CredentialRequestedEvent = {
  credentialId: number;
  issuerId: number;
  creatorId: number;
  credentialType: CredentialType;
};

export type CredentialRevokedEvent = CredentialRequestedEvent & {
  reason: string | null;
  /** Issuer for the issuer's own revoke, admin for a platform-side revoke. */
  revokedByRole: ClerkRole;
};
