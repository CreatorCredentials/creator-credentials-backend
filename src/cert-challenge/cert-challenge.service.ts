import {
  BadRequestException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { In, Repository } from 'typeorm';
import * as crypto from 'crypto';
import { CertChallenge } from './cert-challenge.entity';
import { User } from 'src/users/user.entity';

@Injectable()
export class CertChallengeService {
  constructor(
    @InjectRepository(CertChallenge)
    private certChallengeRepository: Repository<CertChallenge>,
    @InjectRepository(User)
    private userRepository: Repository<User>,
  ) {}

  async getStatus(user: User) {
    const challenge = await this.certChallengeRepository.findOne({
      where: { userId: user.id },
      order: { createdAt: 'DESC' },
    });

    // Heal broken state: verified challenge exists but user column was never written
    if (
      challenge?.status === 'verified' &&
      challenge.certPem &&
      !user.externalCertPem
    ) {
      await this.userRepository.update(
        { id: user.id },
        { externalCertPem: challenge.certPem },
      );
      user.externalCertPem = challenge.certPem;
    }

    return {
      challenge: challenge || null,
      externalCertPem: user.externalCertPem || null,
      activeSigningCertSource: user.activeSigningCertSource,
      commands: challenge ? this.getCommandsForStep(challenge) : null,
    };
  }

  async initiate(user: User) {
    await this.certChallengeRepository.delete({
      userId: user.id,
      status: In(['initiated', 'challenge_issued', 'failed']),
    });

    const challenge = this.certChallengeRepository.create({
      userId: user.id,
      status: 'initiated',
      currentStep: 1,
    });
    const saved = await this.certChallengeRepository.save(challenge);
    return { challenge: saved };
  }

  async submitCert(user: User, certPem: string) {
    const challenge = await this.certChallengeRepository.findOne({
      where: { userId: user.id, status: 'initiated' },
      order: { createdAt: 'DESC' },
    });
    if (!challenge) {
      throw new NotFoundException('No active cert challenge found');
    }

    // Validate X.509 cert
    let x509: crypto.X509Certificate;
    try {
      x509 = new crypto.X509Certificate(certPem);
    } catch {
      throw new BadRequestException('Invalid X.509 certificate PEM format');
    }

    if (new Date(x509.validTo) < new Date()) {
      throw new BadRequestException('Certificate has expired');
    }

    const challengeMessage = crypto.randomBytes(32).toString('hex');

    challenge.certPem = certPem;
    challenge.challengeMessage = challengeMessage;
    challenge.status = 'challenge_issued';
    challenge.currentStep = 2;

    const saved = await this.certChallengeRepository.save(challenge);
    return {
      challenge: saved,
      commands: this.getSigningCommands(challengeMessage),
    };
  }

  async verifySignature(user: User, signatureBase64: string) {
    const challenge = await this.certChallengeRepository.findOne({
      where: { userId: user.id, status: 'challenge_issued' },
      order: { createdAt: 'DESC' },
    });
    if (!challenge) {
      throw new NotFoundException('No pending cert challenge found');
    }

    try {
      const x509 = new crypto.X509Certificate(challenge.certPem);
      const publicKey = x509.publicKey;
      const signatureBuffer = Buffer.from(signatureBase64, 'base64');

      const isValid = crypto
        .createVerify('SHA256')
        .update(challenge.challengeMessage)
        .verify(publicKey, signatureBuffer);

      if (!isValid) {
        challenge.status = 'failed';
        await this.certChallengeRepository.save(challenge);
        return { verified: false, error: 'Signature verification failed' };
      }

      challenge.status = 'verified';
      challenge.currentStep = 3;
      challenge.verifiedAt = new Date();
      await this.certChallengeRepository.save(challenge);

      await this.userRepository.update(
        { id: user.id },
        { externalCertPem: challenge.certPem },
      );

      return { verified: true };
    } catch (e) {
      challenge.status = 'failed';
      await this.certChallengeRepository.save(challenge);
      return { verified: false, error: 'Signature verification failed' };
    }
  }

  async reset(user: User) {
    await this.certChallengeRepository.delete({
      userId: user.id,
      status: In(['initiated', 'challenge_issued', 'failed']),
    });
  }

  async removeExternalCert(user: User) {
    await this.certChallengeRepository.delete({ userId: user.id });
    await this.userRepository.update(
      { id: user.id },
      {
        externalCertPem: null,
        activeSigningCertSource: 'platform',
      },
    );
    return this.userRepository.findOne({ where: { id: user.id } });
  }

  async updateActiveSource(user: User, source: 'platform' | 'external') {
    if (source === 'external' && !user.externalCertPem) {
      throw new BadRequestException('No external certificate registered');
    }
    await this.userRepository.update(
      { id: user.id },
      { activeSigningCertSource: source },
    );
    return this.userRepository.findOne({ where: { id: user.id } });
  }

  private getSigningCommands(challengeMessage: string): string[] {
    return [
      `SIG=$(echo -n "${challengeMessage}" | openssl dgst -sha256 -sign your_private_key.pem | base64) && echo "$SIG" && echo "$SIG" | pbcopy`,
    ];
  }

  private getCommandsForStep(challenge: CertChallenge): string[] {
    if (
      challenge.status === 'challenge_issued' &&
      challenge.challengeMessage
    ) {
      return this.getSigningCommands(challenge.challengeMessage);
    }
    return [];
  }
}
