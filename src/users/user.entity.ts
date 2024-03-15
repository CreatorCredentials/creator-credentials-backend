import {
  BaseEntity,
  Column,
  CreateDateColumn,
  Entity,
  PrimaryGeneratedColumn,
  UpdateDateColumn,
  OneToMany,
} from 'typeorm';
import { Credential } from 'src/credentials/credential.entity';
import { Exclude } from 'class-transformer';
export enum ClerkRole {
  Issuer = 'issuer',
  Creator = 'creator',
}

@Entity()
export class User extends BaseEntity {
  @PrimaryGeneratedColumn()
  id: number;
  @Column({
    name: 'clerk_id',
    unique: true,
    nullable: false,
  })
  clerkId: string;

  @Exclude()
  @Column({ name: 'nonce', default: '' })
  nonce: string;

  @Column({
    name: 'clerk_role',
    type: 'enum',
    enum: ClerkRole,
    nullable: false,
    default: ClerkRole.Creator,
  })
  clerkRole: ClerkRole;

  @OneToMany(() => Credential, (credential) => credential.user)
  credentials: Credential[];

  @Column({ unique: true, name: 'public_address', nullable: true })
  publicAddress: string;

  @Column({ unique: true, name: 'domain', nullable: true })
  domain: string;

  @Exclude()
  @Column({ name: 'domain_record', nullable: true })
  domainRecord: string;

  @Column({
    name: 'domain_pending_verifcation',
    nullable: false,
    default: false,
  })
  domainPendingVerifcation: boolean;

  @Column({ unique: true, name: 'did_web', nullable: true })
  didWeb: string;

  @Exclude()
  @Column({ name: 'did_web_well_known', nullable: true, type: 'jsonb' })
  didWebWellKnown: DidWebWellKnown;

  @Column({
    name: 'did_web_pending_verifcation',
    nullable: false,
    default: false,
  })
  didWebPendingVerifcation: boolean;

  //TIMESTAMPS
  @Exclude()
  @Column({
    name: 'did_web_well_known_changed_at',
    type: 'timestamp',
    default: () => 'CURRENT_TIMESTAMP',
    nullable: false,
  })
  didWebWellKnownChangedAt!: Date;

  @Exclude()
  @Column({
    name: 'domain_record_changed_at',
    type: 'timestamp',
    default: () => 'CURRENT_TIMESTAMP',
    nullable: false,
  })
  domainRecordChangedAt!: Date;

  @Exclude()
  @Column({
    name: 'nonce_changed_at',
    type: 'timestamp',
    default: () => 'CURRENT_TIMESTAMP',
    nullable: false,
  })
  nonceChangedAt!: Date;

  @CreateDateColumn({ name: 'created_at' })
  createdAt!: Date;

  @UpdateDateColumn({ name: 'updated_at' })
  updatedAt!: Date;
}

export type VerificationMethod = {
  id: string;
  type: string;
  controller: string;
  publicKeyJwk: {
    kty: string;
    crv: string;
    x: string;
  };
};

export type DidWebWellKnown = {
  '@context': string[];
  id: string;
  value: string;
  verificationMethod: VerificationMethod[];
  authentication: string[];
};
