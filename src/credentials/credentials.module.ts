import { Module, forwardRef } from '@nestjs/common';
import { CredentialsController } from './credentials.controller';
import { CredentialsService } from './credentials.service';
import { TypeOrmModule } from '@nestjs/typeorm';
import { Credential } from './credential.entity';
import { UsersModule } from 'src/users/users.module';
import { HttpModule } from '@nestjs/axios';
import { JwtModule } from '@nestjs/jwt';

@Module({
  imports: [
    TypeOrmModule.forFeature([Credential]),
    forwardRef(() => UsersModule),
    HttpModule,
    JwtModule,
  ],
  providers: [CredentialsService],
  controllers: [CredentialsController],
  exports: [CredentialsService],
})
export class CredentialsModule {}
