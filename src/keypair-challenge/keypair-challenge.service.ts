import {
  BadRequestException,
  ConflictException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { In, Repository } from 'typeorm';
import * as crypto from 'crypto';
import { publicKeyPemToDid, didToPublicKeyPem } from 'src/shared/did-key.util';
import { KeypairChallenge } from './keypair-challenge.entity';
import { User } from 'src/users/user.entity';

// Statuses we treat as "in progress" — superseded by any new initiate / reset.
const IN_PROGRESS_STATUSES: KeypairChallenge['status'][] = [
  'initiated',
  'challenge_issued',
  'failed',
];

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

    // The keypair challenge is intentionally NOT persisted on the user. The
    // only "external did key" we surface is the one tied to the latest
    // verified-but-not-yet-consumed challenge — i.e. a keypair the creator
    // has just proven ownership of and is ready to use for the credential
    // they are currently requesting. Once the credential request is sent,
    // that challenge gets consumed and this returns null again.
    const activeVerifiedChallenge =
      challenge && challenge.status === 'verified' ? challenge : null;

    return {
      challenge: challenge || null,
      externalDidKey: activeVerifiedChallenge?.derivedDidKey ?? null,
      activeDidKeySource: activeVerifiedChallenge ? 'external' : 'platform',
      commands: challenge ? this.getCommandsForStep(challenge) : null,
    };
  }

  async initiate(user: User, keyFilePrefix?: string) {
    // Wipe both in-progress AND any previously verified-but-unconsumed
    // challenges so that every credential request starts a brand new
    // challenge from scratch. A keypair proof is single-use.
    await this.keypairChallengeRepository.delete({
      userId: user.id,
      status: In([...IN_PROGRESS_STATUSES, 'verified']),
    });

    const prefix = this.sanitizeKeyFilePrefix(keyFilePrefix);

    const challenge = this.keypairChallengeRepository.create({
      userId: user.id,
      status: 'initiated',
      currentStep: 1,
    });
    const saved = await this.keypairChallengeRepository.save(challenge);
    return {
      challenge: saved,
      commands: this.getGenerationCommands(prefix),
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

    const derivedDidKey = publicKeyPemToDid(publicKeyPem);

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

      // Intentionally NOT writing the verified key to the user record.
      // The verified challenge is ephemeral and is consumed at credential
      // request time — see consumeLatestVerified().

      return { verified: true, didKey: challenge.derivedDidKey };
    } catch (e) {
      challenge.status = 'failed';
      await this.keypairChallengeRepository.save(challenge);
      return { verified: false, error: 'Signature verification failed' };
    }
  }

  /**
   * Returns true if the user has a verified-but-not-yet-consumed keypair
   * challenge, without consuming it. Used to determine the credential type
   * before any side-effects are committed.
   */
  async hasVerifiedChallenge(user: User): Promise<boolean> {
    const challenge = await this.keypairChallengeRepository.findOne({
      where: { userId: user.id, status: 'verified' },
    });
    return !!challenge;
  }

  /**
   * Atomically consumes the latest verified-but-unused keypair challenge for
   * the user, returning the derived did:key and public key PEM that should be
   * embedded into the credential being requested. If no verified challenge
   * exists (or it has already been consumed) this returns null and the caller
   * should treat that as "creator has not proven ownership of a keypair for
   * this credential request".
   */
  async consumeLatestVerified(
    user: User,
    credentialId?: number,
  ): Promise<{ derivedDidKey: string; publicKeyPem: string } | null> {
    const challenge = await this.keypairChallengeRepository.findOne({
      where: { userId: user.id, status: 'verified' },
      order: { createdAt: 'DESC' },
    });
    if (!challenge) return null;

    if (!challenge.derivedDidKey || !challenge.publicKeyPem) {
      throw new ConflictException(
        'Verified keypair challenge is missing key material; please restart the keypair challenge.',
      );
    }

    const snapshot = {
      derivedDidKey: challenge.derivedDidKey,
      publicKeyPem: challenge.publicKeyPem,
    };

    challenge.status = 'consumed';
    challenge.consumedAt = new Date();
    if (credentialId) challenge.consumedByCredentialId = credentialId;
    await this.keypairChallengeRepository.save(challenge);

    return snapshot;
  }

  async reset(user: User) {
    // Reset wipes every non-terminal challenge state so the creator can
    // start a fresh proof from scratch. Consumed challenges are kept as
    // an audit trail of which keys signed which credentials.
    await this.keypairChallengeRepository.delete({
      userId: user.id,
      status: In([...IN_PROGRESS_STATUSES, 'verified']),
    });
  }

  async removeExternalKey(user: User) {
    // Legacy endpoint — the user table no longer stores any keypair fields,
    // but consumers may still call this to wipe in-progress / verified rows
    // and force a clean slate. Consumed (audit) rows are preserved.
    await this.keypairChallengeRepository.delete({
      userId: user.id,
      status: In([...IN_PROGRESS_STATUSES, 'verified']),
    });
    return this.userRepository.findOne({ where: { id: user.id } });
  }

  getPublicKeyPemFromDid(did: string): { publicKeyPem: string } {
    return { publicKeyPem: didToPublicKeyPem(did) };
  }

  async updateActiveSource(user: User, _source: 'platform' | 'external') {
    // The active-source toggle was meaningful when we kept a long-lived
    // external did:key on the user. With per-credential challenges the
    // source is determined per-request automatically, so this endpoint
    // is now a no-op kept for backwards compatibility.
    return this.userRepository.findOne({ where: { id: user.id } });
  }

  private sanitizeKeyFilePrefix(prefix?: string): string {
    if (!prefix) return '';
    return prefix
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, '_')
      .replace(/^_+|_+$/g, '');
  }

  private buildKeyFileNames(prefix?: string): {
    privateKey: string;
    publicKey: string;
  } {
    const base = prefix ? `${prefix}_` : 'cc_';
    return {
      privateKey: `${base}private_key.pem`,
      publicKey: `${base}public_key.pem`,
    };
  }

  private getGenerationCommands(prefix?: string): string[] {
    const { privateKey, publicKey } = this.buildKeyFileNames(prefix);
    return [
      `openssl ecparam -name prime256v1 -genkey -noout -out ${privateKey}`,
      `openssl ec -in ${privateKey} -pubout -out ${publicKey}`,
      `cat ${publicKey} | pbcopy`,
    ];
  }

  private getSigningCommands(challengeMessage: string, prefix?: string): string[] {
    const { privateKey } = this.buildKeyFileNames(prefix);
    return [
      `SIG=$(echo -n "${challengeMessage}" | openssl dgst -sha256 -sign ${privateKey} | base64) && echo "$SIG" && echo "$SIG" | pbcopy`,
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
