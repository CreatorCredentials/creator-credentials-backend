import { Module, forwardRef } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { KeypairChallenge } from './keypair-challenge.entity';
import { KeypairChallengeController } from './keypair-challenge.controller';
import { KeypairChallengeService } from './keypair-challenge.service';
import { User } from 'src/users/user.entity';
import { UsersModule } from 'src/users/users.module';

@Module({
  imports: [
    TypeOrmModule.forFeature([KeypairChallenge, User]),
    forwardRef(() => UsersModule),
  ],
  controllers: [KeypairChallengeController],
  providers: [KeypairChallengeService],
  exports: [KeypairChallengeService, TypeOrmModule],
})
export class KeypairChallengeModule {}
