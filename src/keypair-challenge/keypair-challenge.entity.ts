import {
  BaseEntity,
  Column,
  CreateDateColumn,
  Entity,
  JoinColumn,
  ManyToOne,
  PrimaryGeneratedColumn,
  UpdateDateColumn,
} from 'typeorm';
import { User } from 'src/users/user.entity';

export type KeypairChallengeStatus =
  | 'initiated'
  | 'challenge_issued'
  | 'verified'
  | 'consumed'
  | 'failed';

@Entity('keypair_challenge')
export class KeypairChallenge extends BaseEntity {
  @PrimaryGeneratedColumn()
  id: number;

  @Column({ name: 'user_id' })
  userId: number;

  @ManyToOne(() => User, (user) => user.keypairChallenges, {
    eager: false,
    nullable: false,
  })
  @JoinColumn({ name: 'user_id' })
  user: User;

  @Column({ name: 'public_key_pem', type: 'text', nullable: true })
  publicKeyPem: string;

  @Column({ name: 'derived_did_key', type: 'text', nullable: true })
  derivedDidKey: string;

  @Column({ name: 'challenge_message', type: 'text', nullable: true })
  challengeMessage: string;

  @Column({
    name: 'status',
    type: 'enum',
    enum: ['initiated', 'challenge_issued', 'verified', 'consumed', 'failed'],
    enumName: 'keypair_challenge_status_enum',
    default: 'initiated',
  })
  status: KeypairChallengeStatus;

  @Column({ name: 'current_step', default: 1 })
  currentStep: number;

  @Column({ name: 'verified_at', type: 'timestamp', nullable: true })
  verifiedAt: Date;

  @Column({ name: 'consumed_at', type: 'timestamp', nullable: true })
  consumedAt: Date;

  @Column({ name: 'consumed_by_credential_id', type: 'integer', nullable: true })
  consumedByCredentialId: number;

  @CreateDateColumn({ name: 'created_at' })
  createdAt: Date;

  @UpdateDateColumn({ name: 'updated_at' })
  updatedAt: Date;
}
