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
import { CertChallengeService } from './cert-challenge.service';

@Controller('cert-challenge')
export class CertChallengeController {
  constructor(private readonly certChallengeService: CertChallengeService) {}

  @UseGuards(AuthGuard)
  @Get('status')
  getStatus(@GetUser() user: User) {
    return this.certChallengeService.getStatus(user);
  }

  @UseGuards(AuthGuard)
  @Post('initiate')
  initiate(@GetUser() user: User) {
    return this.certChallengeService.initiate(user);
  }

  @UseGuards(AuthGuard)
  @Post('submit-cert')
  submitCert(@GetUser() user: User, @Body('certPem') certPem: string) {
    return this.certChallengeService.submitCert(user, certPem);
  }

  @UseGuards(AuthGuard)
  @Post('verify-signature')
  verifySignature(
    @GetUser() user: User,
    @Body('signature') signature: string,
  ) {
    return this.certChallengeService.verifySignature(user, signature);
  }

  @UseGuards(AuthGuard)
  @Post('reset')
  reset(@GetUser() user: User) {
    return this.certChallengeService.reset(user);
  }

  @UseGuards(AuthGuard)
  @Delete('external-cert')
  removeExternalCert(@GetUser() user: User) {
    return this.certChallengeService.removeExternalCert(user);
  }

  @UseGuards(AuthGuard)
  @Patch('active-source')
  updateActiveSource(
    @GetUser() user: User,
    @Body('source') source: 'platform' | 'external',
  ) {
    return this.certChallengeService.updateActiveSource(user, source);
  }
}
