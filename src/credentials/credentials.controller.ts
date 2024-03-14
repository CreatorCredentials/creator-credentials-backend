import { Controller, Get, Post, Body, UseGuards } from '@nestjs/common';
import { CredentialsService } from './credentials.service';
import { CreateEmailCredentialDto } from './dto/create-email-credential.dto';
import { AuthGuard } from 'src/users/guards/clerk-user.guard';
import { GetUser } from 'src/users/get-user.decorator';
import { User } from 'src/users/user.entity';

@Controller('credentials')
export class CredentialsController {
  constructor(private readonly credentialsService: CredentialsService) {}

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
  @Get('email')
  async getEmailCredentialOfUser(@GetUser() user: User) {
    const emailCredential =
      await this.credentialsService.getEmailCredentialOfUser(user);
    const walletCredential =
      await this.credentialsService.getWalletCredentialOfUser(user);

    return {
      emailCredential,
      walletCredential,
    };
  }
}
