import {
  BadRequestException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { In, Repository } from 'typeorm';
import * as crypto from 'crypto';
import * as baseX from 'base-x';
import { KeypairChallenge } from './keypair-challenge.entity';
import { User } from 'src/users/user.entity';

@Injectable()
export class KeypairChallengeService {
  constructor(
    @InjectRepository(KeypairChallenge)
    private keypairChallengeRepository: Repository<KeypairChallenge>,
    @InjectRepository(User)
    private userRepository: Repository<User>,
  ) {}

  async getStatus(user: User) {
    const challenge = await this.keypairChallengeRepository.findOne({
      where: { userId: user.id },
      order: { createdAt: 'DESC' },
    });

    // Heal broken state: verified challenge exists but user columns were never written
    if (
      challenge?.status === 'verified' &&
      challenge.derivedDidKey &&
      !user.externalDidKey
    ) {
      await this.userRepository.update(
        { id: user.id },
        {
          externalDidKey: challenge.derivedDidKey,
          externalPublicKeyPem: challenge.publicKeyPem,
        },
      );
      user.externalDidKey = challenge.derivedDidKey;
      user.externalPublicKeyPem = challenge.publicKeyPem;
    }

    return {
      challenge: challenge || null,
      externalDidKey: user.externalDidKey || null,
      activeDidKeySource: user.activeDidKeySource,
      commands: challenge ? this.getCommandsForStep(challenge) : null,
    };
  }

  async initiate(user: User) {
    await this.keypairChallengeRepository.delete({
      userId: user.id,
      status: In(['initiated', 'challenge_issued', 'failed']),
    });

    const challenge = this.keypairChallengeRepository.create({
      userId: user.id,
      status: 'initiated',
      currentStep: 1,
    });
    const saved = await this.keypairChallengeRepository.save(challenge);
    return {
      challenge: saved,
      commands: this.getGenerationCommands(),
    };
  }

  async submitPublicKey(user: User, publicKeyPem: string) {
    const challenge = await this.keypairChallengeRepository.findOne({
      where: { userId: user.id, status: 'initiated' },
      order: { createdAt: 'DESC' },
    });
    if (!challenge) {
      throw new NotFoundException('No active keypair challenge found');
    }

    try {
      const keyObject = crypto.createPublicKey(publicKeyPem);
      const jwk = keyObject.export({ format: 'jwk' });
      if ((jwk as any).kty !== 'EC' || (jwk as any).crv !== 'P-256') {
        throw new BadRequestException('Only EC P-256 keys are supported');
      }
    } catch (e) {
      if (e instanceof BadRequestException) throw e;
      throw new BadRequestException('Invalid public key PEM format');
    }

    const challengeMessage = crypto.randomBytes(32).toString('hex');

    const keyObject = crypto.createPublicKey(publicKeyPem);
    const spkiDer = keyObject.export({ type: 'spki', format: 'der' }) as Buffer;
    const hash = crypto.createHash('sha256').update(spkiDer).digest();
    const base58Alphabet =
      '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
    const base58 = baseX(base58Alphabet);
    const derivedDidKey = `did:key:${base58.encode(hash)}`;

    challenge.publicKeyPem = publicKeyPem;
    challenge.challengeMessage = challengeMessage;
    challenge.derivedDidKey = derivedDidKey;
    challenge.status = 'challenge_issued';
    challenge.currentStep = 2;

    const saved = await this.keypairChallengeRepository.save(challenge);
    return {
      challenge: saved,
      commands: this.getSigningCommands(challengeMessage),
    };
  }

  async verifySignature(user: User, signatureBase64: string) {
    const challenge = await this.keypairChallengeRepository.findOne({
      where: { userId: user.id, status: 'challenge_issued' },
      order: { createdAt: 'DESC' },
    });
    if (!challenge) {
      throw new NotFoundException('No pending challenge found');
    }

    try {
      const publicKey = crypto.createPublicKey(challenge.publicKeyPem);
      const signatureBuffer = Buffer.from(signatureBase64, 'base64');
      const isValid = crypto
        .createVerify('SHA256')
        .update(challenge.challengeMessage)
        .verify(publicKey, signatureBuffer);

      if (!isValid) {
        challenge.status = 'failed';
        await this.keypairChallengeRepository.save(challenge);
        return { verified: false, error: 'Signature verification failed' };
      }

      challenge.status = 'verified';
      challenge.currentStep = 3;
      challenge.verifiedAt = new Date();
      await this.keypairChallengeRepository.save(challenge);

      await this.userRepository.update(
        { id: user.id },
        {
          externalDidKey: challenge.derivedDidKey,
          externalPublicKeyPem: challenge.publicKeyPem,
        },
      );

      return { verified: true, didKey: challenge.derivedDidKey };
    } catch (e) {
      challenge.status = 'failed';
      await this.keypairChallengeRepository.save(challenge);
      return { verified: false, error: 'Signature verification failed' };
    }
  }

  async reset(user: User) {
    await this.keypairChallengeRepository.delete({
      userId: user.id,
      status: In(['initiated', 'challenge_issued', 'failed']),
    });
  }

  async removeExternalKey(user: User) {
    await this.keypairChallengeRepository.delete({ userId: user.id });
    await this.userRepository.update(
      { id: user.id },
      {
        externalDidKey: null,
        externalPublicKeyPem: null,
        activeDidKeySource: 'platform',
      },
    );
    return this.userRepository.findOne({ where: { id: user.id } });
  }

  async updateActiveSource(user: User, source: 'platform' | 'external') {
    if (source === 'external' && !user.externalDidKey) {
      throw new BadRequestException('No external DID key registered');
    }
    await this.userRepository.update({ id: user.id }, { activeDidKeySource: source });
    return this.userRepository.findOne({ where: { id: user.id } });
  }

  private getGenerationCommands(): string[] {
    return [
      'openssl ecparam -name prime256v1 -genkey -noout -out cc_private_key.pem',
      'openssl ec -in cc_private_key.pem -pubout -out cc_public_key.pem',
      'cat cc_public_key.pem | pbcopy',
    ];
  }

  private getSigningCommands(challengeMessage: string): string[] {
    return [
      `SIG=$(echo -n "${challengeMessage}" | openssl dgst -sha256 -sign cc_private_key.pem | base64) && echo "$SIG" && echo "$SIG" | pbcopy`,
    ];
  }

  private getCommandsForStep(challenge: KeypairChallenge): string[] {
    if (challenge.status === 'initiated') return this.getGenerationCommands();
    if (
      challenge.status === 'challenge_issued' &&
      challenge.challengeMessage
    ) {
      return this.getSigningCommands(challenge.challengeMessage);
    }
    return [];
  }
}
