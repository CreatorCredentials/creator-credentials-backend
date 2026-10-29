import { Body, Controller, HttpCode, HttpStatus, Post } from '@nestjs/common';
import { VerificationService } from './verification.service';

/** Public: anyone holding a credential can check it; excluded from the Clerk gate. */
@Controller('credentials')
export class VerificationController {
  constructor(private readonly verificationService: VerificationService) {}

  @Post('verify')
  @HttpCode(HttpStatus.OK)
  verify(@Body() body: unknown) {
    return this.verificationService.verify(body);
  }
}
