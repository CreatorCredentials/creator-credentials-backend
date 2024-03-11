import { Controller, Get, Post, Param, UseGuards, Body } from '@nestjs/common';
import { UsersService } from './users.service';
import { GetClerkUserAuth } from './get-clerk-auth.decorator';
import { type AuthObject, clerkClient } from '@clerk/clerk-sdk-node';
import { ClerkRole, User } from './user.entity';
import { AuthGuard } from './guards/clerk-user.guard';
import { GetUser } from './get-user.decorator';

@Controller('users')
export class UsersController {
  constructor(private readonly usersService: UsersService) {}

  @Post('register')
  async registerUser(@GetClerkUserAuth() auth: AuthObject) {
    const clerkUser = await clerkClient.users.getUser(auth.userId);

    let role: ClerkRole;
    switch (clerkUser.publicMetadata.role) {
      case 'CREATOR':
        role = ClerkRole.Creator;
        break;
      case 'ISSUER':
        role = ClerkRole.Issuer;
        break;
    }

    return this.usersService.create({
      clerkId: auth.userId,
      clerkRole: role,
    });
  }

  @UseGuards(AuthGuard)
  @Get()
  async getUserById(@GetUser() user: User) {
    return user;
  }

  @Get('check/:clerkId')
  async getUserByClerkId(@Param('clerkId') clerkId: string) {
    return this.usersService.getByClerkId(clerkId);
  }

  @UseGuards(AuthGuard)
  @Get('nonce')
  async provideNonceOfUser(@GetUser() user: User) {
    return this.usersService.provideNonceForUser(user.clerkId);
  }

  @UseGuards(AuthGuard)
  @Post('address/connect')
  async connectPublicAddressToUser(
    @GetUser() user: User,
    @Body('publicAddress') publicAddress: string,
    @Body('signedMessage') signedMessage: string,
  ) {
    return this.usersService.verifySignatureAndConnectAddress(
      user.clerkId,
      publicAddress,
      signedMessage,
    );
  }
  @UseGuards(AuthGuard)
  @Post('address/disconnect')
  async disconnectPublicAddressToUser(@GetUser() user: User) {
    return this.usersService.disconnectAddress(user.clerkId);
  }
}
