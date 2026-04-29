import { CanActivate, ExecutionContext, Injectable } from '@nestjs/common';
import type { WithAuthProp } from '@clerk/clerk-sdk-node';
import { type Request } from 'express';
import { UsersService } from '../users.service';

@Injectable()
export class AuthGuard implements CanActivate {
  constructor(private usersService: UsersService) {}
  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest<WithAuthProp<Request> & { user?: unknown }>();
    const userId = request.auth?.userId;
    if (!userId) return false;

    const user = await this.usersService.getByClerkId(userId);
    request.user = user;
    return !!user;
  }
}
