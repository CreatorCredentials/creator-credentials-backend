import { SetMetadata } from '@nestjs/common';
import { ClerkRole } from '../user.entity';

export const ROLES_KEY = 'roles';

/** Roles allowed on a route or controller; enforced by RolesGuard after AuthGuard. */
export const Roles = (...roles: ClerkRole[]) => SetMetadata(ROLES_KEY, roles);
