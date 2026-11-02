import { Test, TestingModule } from '@nestjs/testing';
import { getRepositoryToken } from '@nestjs/typeorm';
import { Credential } from 'src/credentials/credential.entity';
import { CredentialVerificationStatus } from 'src/shared/typings/CredentialVerificationStatus';
import { IssuedCredentialRecordsService } from './issued-credential-records.service';

const TOKEN = 'eyJhbGciOiJSUzI1NiJ9.eyJpZCI6InVybjp1dWlkOjEifQ.c2ln';

describe('IssuedCredentialRecordsService', () => {
  const repository = { findOne: jest.fn() };
  let service: IssuedCredentialRecordsService;

  beforeEach(async () => {
    jest.resetAllMocks();
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        IssuedCredentialRecordsService,
        { provide: getRepositoryToken(Credential), useValue: repository },
      ],
    }).compile();
    service = module.get(IssuedCredentialRecordsService);
  });

  it('looks the credential up by its exact token', async () => {
    repository.findOne.mockResolvedValue({
      id: 7,
      credentialStatus: CredentialVerificationStatus.Success,
    });

    await service.stateOfToken(TOKEN);

    expect(repository.findOne).toHaveBeenCalledWith({
      where: { token: TOKEN },
      select: { id: true, credentialStatus: true },
    });
  });

  it('is revoked for a REVOKED record', async () => {
    repository.findOne.mockResolvedValue({
      id: 7,
      credentialStatus: CredentialVerificationStatus.Revoked,
    });

    await expect(service.stateOfToken(TOKEN)).resolves.toBe('revoked');
  });

  it('is valid for a SUCCESS record', async () => {
    repository.findOne.mockResolvedValue({
      id: 7,
      credentialStatus: CredentialVerificationStatus.Success,
    });

    await expect(service.stateOfToken(TOKEN)).resolves.toBe('valid');
  });

  it('is unknown for a token the platform never issued', async () => {
    repository.findOne.mockResolvedValue(null);

    await expect(service.stateOfToken(TOKEN)).resolves.toBe('unknown');
  });

  it('is unknown for a record in a state other than issued or revoked', async () => {
    repository.findOne.mockResolvedValue({
      id: 7,
      credentialStatus: CredentialVerificationStatus.Pending,
    });

    await expect(service.stateOfToken(TOKEN)).resolves.toBe('unknown');
  });
});
