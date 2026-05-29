import { createParamDecorator, ExecutionContext } from '@nestjs/common';
import type { WithAuthProp } from '@clerk/clerk-sdk-node';
import { type Request } from 'express';

export const GetClerkUserAuth = createParamDecorator(
  (data: unknown, ctx: ExecutionContext) => {
    const request = ctx.switchToHttp().getRequest<WithAuthProp<Request>>();
    return request.auth;
  },
);
