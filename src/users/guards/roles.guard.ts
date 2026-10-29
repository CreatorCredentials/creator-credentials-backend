import {
  CanActivate,
  ExecutionContext,
  ForbiddenException,
  Injectable,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { ClerkRole, User } from '../user.entity';
import { ROLES_KEY } from './roles.decorator';

/**
 * Allows the request when the loaded user has one of the roles declared with
 * `@Roles()`. Runs after AuthGuard, which puts the user on the request; a
 * route without `@Roles()` is open to every authenticated role.
 */
@Injectable()
export class RolesGuard implements CanActivate {
  constructor(private readonly reflector: Reflector) {}

  canActivate(context: ExecutionContext): boolean {
    const allowedRoles = this.reflector.getAllAndOverride<ClerkRole[]>(
      ROLES_KEY,
      [context.getHandler(), context.getClass()],
    );
    if (!allowedRoles?.length) {
      return true;
    }

    const { user } = context
      .switchToHttp()
      .getRequest<{ user?: Pick<User, 'clerkRole'> }>();
    if (!user || !allowedRoles.includes(user.clerkRole)) {
      throw new ForbiddenException('This api is not available to your role.');
    }
    return true;
  }
}
