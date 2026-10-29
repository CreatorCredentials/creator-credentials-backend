import { ExecutionContext, ForbiddenException } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { ClerkRole } from '../user.entity';
import { ROLES_KEY } from './roles.decorator';
import { RolesGuard } from './roles.guard';

function buildContext(user?: { clerkRole: ClerkRole }): ExecutionContext {
  return {
    getHandler: () => 'handler',
    getClass: () => 'class',
    switchToHttp: () => ({ getRequest: () => ({ user }) }),
  } as unknown as ExecutionContext;
}

describe('RolesGuard', () => {
  const reflector = { getAllAndOverride: jest.fn() };
  const guard = new RolesGuard(reflector as unknown as Reflector);

  beforeEach(() => jest.resetAllMocks());

  it('allows a user whose role is declared on the route', () => {
    reflector.getAllAndOverride.mockReturnValue([ClerkRole.Admin]);

    expect(
      guard.canActivate(buildContext({ clerkRole: ClerkRole.Admin })),
    ).toBe(true);
    expect(reflector.getAllAndOverride).toHaveBeenCalledWith(ROLES_KEY, [
      'handler',
      'class',
    ]);
  });

  it('rejects a user of another role with 403', () => {
    reflector.getAllAndOverride.mockReturnValue([ClerkRole.Admin]);

    expect(() =>
      guard.canActivate(buildContext({ clerkRole: ClerkRole.Issuer })),
    ).toThrow(ForbiddenException);
  });

  it('rejects a request without a loaded user', () => {
    reflector.getAllAndOverride.mockReturnValue([ClerkRole.Admin]);

    expect(() => guard.canActivate(buildContext(undefined))).toThrow(
      ForbiddenException,
    );
  });

  it('leaves a route without @Roles open to every authenticated role', () => {
    reflector.getAllAndOverride.mockReturnValue(undefined);

    expect(
      guard.canActivate(buildContext({ clerkRole: ClerkRole.Creator })),
    ).toBe(true);
  });
});
