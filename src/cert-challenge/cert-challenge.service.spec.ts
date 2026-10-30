import { GoneException, NotFoundException } from '@nestjs/common';
import { Repository } from 'typeorm';
import { User } from 'src/users/user.entity';
import { CertChallenge } from './cert-challenge.entity';
import { CertChallengeService } from './cert-challenge.service';
import { CertValidatorService } from './validation/cert-validator.service';

const HOUR_MS = 60 * 60 * 1000;

function buildChallenge(overrides: Partial<CertChallenge>): CertChallenge {
  return Object.assign(new CertChallenge(), {
    id: 1,
    userId: 7,
    status: 'challenge_issued',
    challengeMessage: 'nonce',
    ...overrides,
  });
}

describe('CertChallengeService.verifySignature', () => {
  const user = Object.assign(new User(), { id: 7 });
  const challenges = { findOne: jest.fn(), save: jest.fn() };
  const users = { update: jest.fn() };
  let service: CertChallengeService;

  beforeEach(() => {
    jest.resetAllMocks();
    challenges.save.mockImplementation(async (c: CertChallenge) => c);
    service = new CertChallengeService(
      challenges as unknown as Repository<CertChallenge>,
      users as unknown as Repository<User>,
      {} as CertValidatorService,
    );
  });

  it('requires a pending challenge', async () => {
    challenges.findOne.mockResolvedValue(null);

    await expect(service.verifySignature(user, 'sig')).rejects.toThrow(
      NotFoundException,
    );
  });

  it('fails an expired challenge with 410 and never touches the user', async () => {
    const challenge = buildChallenge({
      expiresAt: new Date(Date.now() - HOUR_MS),
    });
    challenges.findOne.mockResolvedValue(challenge);

    await expect(service.verifySignature(user, 'sig')).rejects.toThrow(
      GoneException,
    );

    expect(challenge.status).toBe('failed');
    expect(challenges.save).toHaveBeenCalledWith(challenge);
    expect(users.update).not.toHaveBeenCalled();
  });

  it('still verifies a challenge that has not expired', async () => {
    const challenge = buildChallenge({
      expiresAt: new Date(Date.now() + HOUR_MS),
      certPem: 'not a certificate',
    });
    challenges.findOne.mockResolvedValue(challenge);

    const result = await service.verifySignature(user, 'sig');

    expect(result).toEqual({
      verified: false,
      error: 'Signature verification failed',
    });
    expect(challenge.status).toBe('failed');
  });
});
