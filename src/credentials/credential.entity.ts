import {
  BaseEntity,
  Column,
  CreateDateColumn,
  Entity,
  PrimaryGeneratedColumn,
  UpdateDateColumn,
  ManyToOne,
  JoinColumn,
} from 'typeorm';
import { Exclude } from 'class-transformer';
import { User } from 'src/users/user.entity';

//TO DO, Use full credential from shared typings later
export enum CredentialType {
  EMail = 'EMAIL',
  Wallet = 'WALLET',
  Domain = 'DOMAIN',
  Member = 'MEMBER',
  DidWeb = 'DID_WEB',
}

export enum CredentialVerificationStatus {
  Pending = 'PENDING',
  Success = 'SUCCESS',
  Failed = 'FAILED',
}

@Entity()
export class Credential extends BaseEntity {
  @PrimaryGeneratedColumn()
  id: number;

  @Column({ nullable: false })
  email: string; //TODO: rename to credential value with all data transfer

  @Column({ nullable: false })
  token: string;

  @Column({ type: 'jsonb', nullable: false })
  credentialObject: any;

  @Exclude()
  @ManyToOne(() => User, (user) => user.credentials, {
    eager: false,
    nullable: false,
  })
  @JoinColumn({ name: 'user_id' })
  user: User;

  @Exclude()
  @Column({ name: 'user_id' })
  userId: number;

  @Column({
    name: 'credential_type',
    type: 'enum',
    enum: CredentialType,
    nullable: false,
    default: CredentialType.EMail,
  })
  credentialType: CredentialType;

  @Column({
    name: 'credential_status',
    type: 'enum',
    enum: CredentialVerificationStatus,
    nullable: false,
    default: CredentialVerificationStatus.Pending,
  })
  credentialStatus: CredentialVerificationStatus;

  //TIMESTAMPS

  @CreateDateColumn({ name: 'created_at' })
  createdAt!: Date;

  @UpdateDateColumn({ name: 'updated_at' })
  updatedAt!: Date;
}
