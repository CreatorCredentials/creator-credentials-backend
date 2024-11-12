import {
  Controller,
  Get,
  Post,
  Body,
  UseGuards,
  NotFoundException,
  ParseIntPipe,
  Param,
  Query,
  Delete,
  UnauthorizedException,
  HttpException,
  HttpStatus,
  RawBodyRequest,
  Req,
} from '@nestjs/common';
import { CredentialsService } from './credentials.service';
import { CreateEmailCredentialDto } from './dto/create-email-credential.dto';
import { AuthGuard } from 'src/users/guards/clerk-user.guard';
import { GetUser } from 'src/users/get-user.decorator';
import { ClerkRole, User } from 'src/users/user.entity';
import { CredentialVerificationStatus } from 'src/shared/typings/CredentialVerificationStatus';
import { formatCredentialForUnion } from './credentials.formatters';
import { CredentialType } from 'src/shared/typings/CredentialType';
import { UsersService } from 'src/users/users.service';
import { Token, createClerkClient } from '@clerk/clerk-sdk-node';
import * as jwt from 'jsonwebtoken';
import axios from 'axios';
import { TimeoutError, catchError, firstValueFrom } from 'rxjs';
import { HttpService } from '@nestjs/axios';
import { promisify } from 'util';
import { JwtService } from '@nestjs/jwt';
import { KeyObject, createPublicKey } from 'crypto';

const verifyAsync = promisify(jwt.verify);

@Controller('credentials')
export class CredentialsController {
  constructor(
    private readonly credentialsService: CredentialsService,
    private readonly usersService: UsersService,
    private readonly httpService: HttpService,
    private readonly jwtService: JwtService,
  ) {}

  @UseGuards(AuthGuard)
  @Post('create/email')
  async createEmailCredential(
    @Body() createCredentialDto: CreateEmailCredentialDto,
    @GetUser() user: User,
  ) {
    return this.credentialsService.createEmailCredential(
      createCredentialDto,
      user,
    );
  }

  @UseGuards(AuthGuard)
  @Get('issuers')
  async getIssuers(
    @GetUser() user: User,
    @Query('status') status: CredentialVerificationStatus,
  ) {
    if (user.clerkRole !== ClerkRole.Issuer) {
      throw new NotFoundException('This api is only for issuers.');
    }
    const credentials =
      await this.credentialsService.getAllIssuersMemberCredentialsWithCreators(
        user.id,
        status,
      );
    return { credentials: credentials.map(formatCredentialForUnion) };
  }

  @UseGuards(AuthGuard)
  @Get('issuer')
  async getCredentialsOfIssuer(@GetUser() user: User) {
    if (user.clerkRole !== ClerkRole.Issuer) {
      throw new NotFoundException('This api is only for Issuer.');
    }
    const [
      emailCredential,
      domainCredential,
      didWebCredential,
      memberShipCredentials,
    ] = await Promise.all([
      this.credentialsService.getCredentialsOfUserByType(
        user,
        CredentialType.EMail,
      ),
      this.credentialsService.getCredentialsOfUserByType(
        user,
        CredentialType.Domain,
      ),
      this.credentialsService.getCredentialsOfUserByType(
        user,
        CredentialType.DidWeb,
      ),
      user.issuedCredentials,
    ]);

    return {
      email: emailCredential[0] && formatCredentialForUnion(emailCredential[0]),
      domain:
        domainCredential[0] && formatCredentialForUnion(domainCredential[0]),
      didWeb:
        didWebCredential[0] && formatCredentialForUnion(didWebCredential[0]),
      membership: memberShipCredentials.map(formatCredentialForUnion),
    };
  }
  @UseGuards(AuthGuard)
  @Get('creator')
  async getCredentialsOfCreator(@GetUser() user: User) {
    if (user.clerkRole !== ClerkRole.Creator) {
      throw new NotFoundException('This api is only for creators.');
    }

    const [
      emailCredential,
      walletCredential,
      domainCredential,
      memberShipCredentials,
      connectCredential,
    ] = await Promise.all([
      this.credentialsService.getCredentialsOfUserByType(
        user,
        CredentialType.EMail,
      ),
      this.credentialsService.getCredentialsOfUserByType(
        user,
        CredentialType.Wallet,
      ),
      this.credentialsService.getCredentialsOfUserByType(
        user,
        CredentialType.Domain,
      ),
      this.credentialsService.getCredentialsOfUserByType(
        user,
        CredentialType.Member,
      ),
      this.credentialsService.getCredentialsOfUserByType(
        user,
        CredentialType.Connect,
      ),
    ]);

    return {
      email: emailCredential[0] && formatCredentialForUnion(emailCredential[0]),
      wallet:
        walletCredential[0] && formatCredentialForUnion(walletCredential[0]),
      domain:
        domainCredential[0] && formatCredentialForUnion(domainCredential[0]),
      membership: memberShipCredentials.map(formatCredentialForUnion),
      connect:
        connectCredential[0] && formatCredentialForUnion(connectCredential[0]),
    };
  }

  @UseGuards(AuthGuard)
  @Post('request')
  async requestCredentialsFromIssuer(
    @GetUser() user: User,
    @Body('issuerId', ParseIntPipe) issuerId: number,
  ) {
    if (user.clerkRole !== ClerkRole.Creator) {
      throw new NotFoundException('This api is only for creators.');
    }
    const issuer = await this.usersService.getByUserId(issuerId);
    if (!issuer || issuer.clerkRole !== ClerkRole.Issuer) {
      throw new NotFoundException('This issuer is not found.');
    }

    if (!issuer.domain && !issuer.didWeb) {
      throw new NotFoundException('This issuer has not verified himself.');
    }

    return this.credentialsService.createPendingMemberCredential(
      { value: issuer.domain || issuer.didWeb, did: user.didKey },
      user,
      issuerId,
    );
  }

  @Post('export')
  async exportCredentialsForUser(@Body('token') token: string) {
    console.log('exportCredentialsForUser called');

    const key: KeyObject = createPublicKey({
      key: {
        use: 'sig',
        kty: 'RSA',
        kid: process.env.LICCIUM_CLERK_KEYS_KID,
        alg: 'RS256',
        n: process.env.LICCIUM_CLERK_KEYS_N,
        e: process.env.LICCIUM_CLERK_KEYS_E,
      },
      format: 'jwk',
    });

    console.log('exportCredentialsForUser key: ', key);

    const exportedKey: string = key
      .export({ type: 'pkcs1', format: 'pem' })
      .toString();

    console.log('exportedKey: ', exportedKey);
    const result = await this.jwtService.verify(token, {
      algorithms: ['RS256'],
      publicKey: exportedKey,
    });
    console.log('result', result);
    console.log('token', token);

    if (!token) {
      throw new UnauthorizedException('Token is required');
    }

    const userEmail = result?.email;

    console.log('userEmail', userEmail);

    if (!result?.sub || !userEmail) {
      throw new UnauthorizedException('Invalid token or email not found');
    }

    const licciumDidKey = result?.licciumDidKey;

    if (!licciumDidKey) {
      throw new NotFoundException(
        "Liccium user doesn' contain licciumDidKey. Import and connection failed",
      );
    }

    interface ClerkUser {
      id: string;
      email_addresses: Array<{
        id: string;
        email_address: string;
        verified: boolean;
      }>;
    }

    interface ClerkApiResponse {
      data: ClerkUser[];
    }

    let users = null;

    try {
      const response = await firstValueFrom<ClerkApiResponse>(
        this.httpService
          .get(
            `https://api.clerk.dev/v1/users?email_address=${encodeURIComponent(
              userEmail,
            )}`,
            {
              headers: {
                Authorization: `Bearer ${process.env.CLERK_SECRET_KEY}`,
              },
            },
          )
          .pipe(
            catchError((err) => {
              throw new HttpException(
                err.message,
                HttpStatus.INTERNAL_SERVER_ERROR,
              );
            }),
          ),
      );
      users = response.data;
    } catch (error) {
      console.log('Error fetching user from Clerk');
      console.log(error);
      users = [];
    }

    console.log('users: ', users);
    if (!users[0]) return;

    const userId = users[0].id;

    const user = await this.usersService.getByClerkId(userId);
    if (user.clerkRole !== ClerkRole.Creator) {
      throw new NotFoundException('This api is only for creators.');
    }

    await this.credentialsService.removeConnectCredential(user);
    await this.credentialsService.createConnectCredential(
      { didKey: user.didKey, licciumDidKey },
      user,
    );

    const [
      emailCredential,
      walletCredential,
      domainCredential,
      memberShipCredentials,
      connectCredential,
    ] = await Promise.all([
      this.credentialsService.getCredentialsOfUserByType(
        user,
        CredentialType.EMail,
      ),
      this.credentialsService.getCredentialsOfUserByType(
        user,
        CredentialType.Wallet,
      ),
      this.credentialsService.getCredentialsOfUserByType(
        user,
        CredentialType.Domain,
      ),
      this.credentialsService.getCredentialsOfUserByType(
        user,
        CredentialType.Member,
      ),
      this.credentialsService.getCredentialsOfUserByType(
        user,
        CredentialType.Connect,
      ),
    ]);

    const credentials = {
      email: emailCredential[0] && formatCredentialForUnion(emailCredential[0]),
      wallet:
        walletCredential[0] && formatCredentialForUnion(walletCredential[0]),
      domain:
        domainCredential[0] && formatCredentialForUnion(domainCredential[0]),
      membership: memberShipCredentials.map(formatCredentialForUnion),
      connect:
        connectCredential[0] && formatCredentialForUnion(connectCredential[0]),
    };

    return { userId, userEmail, credentials };
  }

  @UseGuards(AuthGuard)
  @Post(':credentialId/accept')
  async acceptCredentialByIssuer(
    @GetUser() user: User,
    @Param('credentialId', ParseIntPipe) credentialId: number,
  ) {
    if (user.clerkRole !== ClerkRole.Issuer) {
      throw new NotFoundException('This api is only for Issuers.');
    }

    return this.credentialsService.createMemberCredential(user, credentialId);
  }

  @UseGuards(AuthGuard)
  @Post(':credentialId/reject')
  async rejectCredentialByIssuer(
    @GetUser() user: User,
    @Param('credentialId', ParseIntPipe) credentialId: number,
  ) {
    if (user.clerkRole !== ClerkRole.Issuer) {
      throw new NotFoundException('This api is only for Issuers.');
    }

    return this.credentialsService.removeMemberCredential(credentialId);
  }

  @UseGuards(AuthGuard)
  @Delete(':credentialId')
  async deleteMemberCredentialByIssuer(
    @GetUser() user: User,
    @Param('credentialId', ParseIntPipe) credentialId: number,
  ) {
    if (user.clerkRole !== ClerkRole.Issuer) {
      throw new NotFoundException('This api is only for Issuers.');
    }

    return this.credentialsService.removeMemberCredential(credentialId);
  }
}
