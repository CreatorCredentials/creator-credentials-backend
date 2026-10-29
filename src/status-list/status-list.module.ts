import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { Credential } from 'src/credentials/credential.entity';
import { StatusListController } from './status-list.controller';
import { StatusListService } from './status-list.service';

@Module({
  imports: [TypeOrmModule.forFeature([Credential])],
  providers: [StatusListService],
  controllers: [StatusListController],
  exports: [StatusListService],
})
export class StatusListModule {}
