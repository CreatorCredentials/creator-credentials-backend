import { Module, forwardRef } from '@nestjs/common';
import { CredentialsController } from './credentials.controller';
import { CredentialsService } from './credentials.service';
import { TypeOrmModule } from '@nestjs/typeorm';
import { Credential } from './credential.entity';
import { UsersModule } from 'src/users/users.module';
import { HttpModule } from '@nestjs/axios';
import { JwtModule } from '@nestjs/jwt';
import { KeypairChallengeModule } from 'src/keypair-challenge/keypair-challenge.module';
import { StatusListModule } from 'src/status-list/status-list.module';

@Module({
  imports: [
    TypeOrmModule.forFeature([Credential]),
    forwardRef(() => UsersModule),
    HttpModule,
    JwtModule,
    forwardRef(() => KeypairChallengeModule),
    StatusListModule,
  ],
  providers: [CredentialsService],
  controllers: [CredentialsController],
  exports: [CredentialsService],
})
export class CredentialsModule {}
