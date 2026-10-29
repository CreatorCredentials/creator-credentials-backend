import { ClerkRole, User } from 'src/users/user.entity';

export type UserWithCounts = User & {
  credentialCount: number;
  issuedCredentialCount: number;
};

/** Item of GET admin/users. */
export type AdminUser = {
  id: number;
  role: ClerkRole;
  name: string | null;
  email: string | null;
  didKey: string;
  domain: string | null;
  didWeb: string | null;
  organizationName: string | null;
  createdAt: Date;
  counts: {
    credentials: number;
    issuedCredentials: number;
  };
};

export type AdminStats = {
  users: Record<string, number>;
  credentials: {
    byType: Record<string, number>;
    byStatus: Record<string, number>;
  };
  revocationsLast30Days: number;
  generatedAt: string;
};
