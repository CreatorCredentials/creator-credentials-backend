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

export type CertChallengeStatus =
  | 'initiated'
  | 'challenge_issued'
  | 'verified'
  | 'failed';

@Entity('cert_challenge')
export class CertChallenge extends BaseEntity {
  @PrimaryGeneratedColumn()
  id: number;

  @Column({ name: 'user_id' })
  userId: number;

  @ManyToOne(() => User, (user) => user.certChallenges, {
    eager: false,
    nullable: false,
  })
  @JoinColumn({ name: 'user_id' })
  user: User;

  @Column({ name: 'cert_pem', type: 'text', nullable: true })
  certPem: string;

  @Column({ name: 'cert_fingerprint', type: 'varchar', length: 64, nullable: true })
  certFingerprint: string;

  @Column({ name: 'challenge_message', type: 'text', nullable: true })
  challengeMessage: string;

  @Column({ name: 'expires_at', type: 'timestamp', nullable: true })
  expiresAt: Date;

  @Column({
    name: 'status',
    type: 'enum',
    enum: ['initiated', 'challenge_issued', 'verified', 'failed'],
    enumName: 'cert_challenge_status_enum',
    default: 'initiated',
  })
  status: CertChallengeStatus;

  @Column({ name: 'current_step', default: 1 })
  currentStep: number;

  @Column({ name: 'verified_at', type: 'timestamp', nullable: true })
  verifiedAt: Date;

  @CreateDateColumn({ name: 'created_at' })
  createdAt: Date;

  @UpdateDateColumn({ name: 'updated_at' })
  updatedAt: Date;
}
