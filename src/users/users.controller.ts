import {
  Controller,
  Get,
  Post,
  Param,
  UseGuards,
  Body,
  HttpCode,
  HttpStatus,
} from '@nestjs/common';
import { UsersService } from './users.service';
import { GetClerkUserAuth } from './get-clerk-auth.decorator';
import { type AuthObject, clerkClient } from '@clerk/clerk-sdk-node';
import { ClerkRole, User } from './user.entity';
import { AuthGuard } from './guards/clerk-user.guard';
import { GetUser } from './get-user.decorator';
import { CredentialsService } from 'src/credentials/credentials.service';

@Controller('users')
export class UsersController {
  constructor(
    private readonly usersService: UsersService,
    private readonly credentialsService: CredentialsService,
  ) {}

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
  @Get('credentials')
  async getEmailCredentialOfUser(@GetUser() user: User) {
    const emailCredential =
      await this.credentialsService.getEmailCredentialOfUser(user);
    const walletCredential =
      await this.credentialsService.getWalletCredentialOfUser(user);

    const domainCredential =
      await this.credentialsService.getDomainCredentialOfUser(user);

    const didWebCredential =
      await this.credentialsService.getDidWebCredentialOfUser(user);

    return {
      email: emailCredential,
      wallet: walletCredential || null,
      domain: domainCredential || null,
      didWeb: didWebCredential || null,
      // membership: MembershipCredential[].
    };
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

  @UseGuards(AuthGuard)
  @Post('verification/domain/txt-record')
  @HttpCode(HttpStatus.CREATED)
  createTxtRecordForDomain(
    @GetUser() user: User,
    @Body('domain') domain: string,
  ) {
    return this.usersService.receiveAndUpdateDomainRecord(user, domain);
  }

  @UseGuards(AuthGuard)
  @Post('verification/domain/confirm')
  @HttpCode(HttpStatus.CREATED)
  confirmDomainTxtRecord(@GetUser() user: User) {
    return this.usersService.confirmDomainRecordCreated(user);
  }

  @UseGuards(AuthGuard)
  @Post('domain/disconnect')
  async disconnectDomainFromUser(@GetUser() user: User) {
    return this.usersService.disconnectDomain(user.clerkId);
  }

  @UseGuards(AuthGuard)
  @Post('verification/did-web/well-known')
  @HttpCode(HttpStatus.CREATED)
  createWellKnownForDidWeb(
    @GetUser() user: User,
    @Body('didWeb') didWeb: string,
  ) {
    return this.usersService.receiveAndUpdateDidWebWellKnown(user, didWeb);
  }

  @UseGuards(AuthGuard)
  @Post('verification/did-web/confirm')
  @HttpCode(HttpStatus.CREATED)
  confirmDidWebWellKnown(@GetUser() user: User) {
    return this.usersService.confirmDidWebWellKnownCreated(user);
  }

  @UseGuards(AuthGuard)
  @Post('did-web/disconnect')
  async disconnectDidWebFromUser(@GetUser() user: User) {
    return this.usersService.disconnectDidWeb(user.clerkId);
  }
}
