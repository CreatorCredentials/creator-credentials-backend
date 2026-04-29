import { Module, forwardRef } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { CertChallenge } from './cert-challenge.entity';
import { CertChallengeController } from './cert-challenge.controller';
import { CertChallengeService } from './cert-challenge.service';
import { User } from 'src/users/user.entity';
import { UsersModule } from 'src/users/users.module';

@Module({
  imports: [
    TypeOrmModule.forFeature([CertChallenge, User]),
    forwardRef(() => UsersModule),
  ],
  controllers: [CertChallengeController],
  providers: [CertChallengeService],
  exports: [CertChallengeService],
})
export class CertChallengeModule {}
