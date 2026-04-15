import {
  Body,
  Controller,
  Delete,
  Get,
  Patch,
  Post,
  UseGuards,
} from '@nestjs/common';
import { AuthGuard } from 'src/users/guards/clerk-user.guard';
import { GetUser } from 'src/users/get-user.decorator';
import { User } from 'src/users/user.entity';
import { KeypairChallengeService } from './keypair-challenge.service';

@Controller('keypair-challenge')
export class KeypairChallengeController {
  constructor(
    private readonly keypairChallengeService: KeypairChallengeService,
  ) {}

  @UseGuards(AuthGuard)
  @Get('status')
  getStatus(@GetUser() user: User) {
    return this.keypairChallengeService.getStatus(user);
  }

  @UseGuards(AuthGuard)
  @Post('initiate')
  initiate(@GetUser() user: User) {
    return this.keypairChallengeService.initiate(user);
  }

  @UseGuards(AuthGuard)
  @Post('submit-public-key')
  submitPublicKey(
    @GetUser() user: User,
    @Body('publicKeyPem') publicKeyPem: string,
  ) {
    return this.keypairChallengeService.submitPublicKey(user, publicKeyPem);
  }

  @UseGuards(AuthGuard)
  @Post('verify-signature')
  verifySignature(
    @GetUser() user: User,
    @Body('signature') signature: string,
  ) {
    return this.keypairChallengeService.verifySignature(user, signature);
  }

  @UseGuards(AuthGuard)
  @Post('reset')
  reset(@GetUser() user: User) {
    return this.keypairChallengeService.reset(user);
  }

  @UseGuards(AuthGuard)
  @Delete('external-key')
  removeExternalKey(@GetUser() user: User) {
    return this.keypairChallengeService.removeExternalKey(user);
  }

  @UseGuards(AuthGuard)
  @Patch('active-source')
  updateActiveSource(
    @GetUser() user: User,
    @Body('source') source: 'platform' | 'external',
  ) {
    return this.keypairChallengeService.updateActiveSource(user, source);
  }
}
