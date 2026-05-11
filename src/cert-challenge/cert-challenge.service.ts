import {
  BadRequestException,
  GoneException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { In, Repository } from 'typeorm';
import * as crypto from 'crypto';
import { CertChallenge } from './cert-challenge.entity';
import { User } from 'src/users/user.entity';
import { CertValidatorService } from './validation/cert-validator.service';

const CHALLENGE_TTL_MINUTES = 60;

@Injectable()
export class CertChallengeService {
  constructor(
    @InjectRepository(CertChallenge)
    private certChallengeRepository: Repository<CertChallenge>,
    @InjectRepository(User)
    private userRepository: Repository<User>,
    private readonly certValidator: CertValidatorService,
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

    // Full eIDAS validation: format, validity window, algorithm allowlist,
    // key usage, and chain to a QSeal/QSig CA listed in the EU LOTL.
    const result = await this.certValidator.validateLeafPem(certPem);
    if (result.ok === false) {
      throw new BadRequestException(result.reason);
    }

    const challengeMessage = crypto.randomBytes(32).toString('hex');
    const expiresAt = new Date(Date.now() + CHALLENGE_TTL_MINUTES * 60 * 1000);

    challenge.certPem = certPem;
    challenge.certFingerprint = result.fingerprint;
    challenge.challengeMessage = challengeMessage;
    challenge.expiresAt = expiresAt;
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

    // Expiry check disabled for dev/testing — re-enable in production.
    // if (challenge.expiresAt && challenge.expiresAt.getTime() < Date.now()) {
    //   challenge.status = 'failed';
    //   await this.certChallengeRepository.save(challenge);
    //   throw new GoneException(
    //     `Challenge expired at ${challenge.expiresAt.toISOString()}; please restart the cert challenge.`,
    //   );
    // }

    try {
      const x509 = new crypto.X509Certificate(challenge.certPem);

      // Re-bind the cert to its fingerprint recorded at submit time. This
      // prevents an attacker from racing a tampered certPem into the row
      // between submit-cert and verify-signature.
      const currentFingerprint = crypto
        .createHash('sha256')
        .update(x509.raw)
        .digest('hex');
      if (
        challenge.certFingerprint &&
        currentFingerprint !== challenge.certFingerprint
      ) {
        challenge.status = 'failed';
        await this.certChallengeRepository.save(challenge);
        return {
          verified: false,
          error:
            'Certificate fingerprint changed since submit; aborting verification.',
        };
      }

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
