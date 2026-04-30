import { Module, forwardRef } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { CertChallenge } from './cert-challenge.entity';
import { CertChallengeController } from './cert-challenge.controller';
import { CertChallengeService } from './cert-challenge.service';
import { User } from 'src/users/user.entity';
import { UsersModule } from 'src/users/users.module';
import { TrustStoreModule } from './trust-store/trust-store.module';
import { CertValidatorService } from './validation/cert-validator.service';

@Module({
  imports: [
    TypeOrmModule.forFeature([CertChallenge, User]),
    forwardRef(() => UsersModule),
    TrustStoreModule,
  ],
  controllers: [CertChallengeController],
  providers: [CertChallengeService, CertValidatorService],
  exports: [CertChallengeService],
})
export class CertChallengeModule {}
