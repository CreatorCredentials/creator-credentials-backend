import { Test, TestingModule } from '@nestjs/testing';
import { getRepositoryToken } from '@nestjs/typeorm';
import { TemplatesService } from './templates.service';
import { Template } from './template.entity';
import { User } from 'src/users/user.entity';

describe('TemplatesService', () => {
  const templatesRepository = { find: jest.fn() };
  let service: TemplatesService;

  beforeEach(async () => {
    jest.resetAllMocks();

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        TemplatesService,
        {
          provide: getRepositoryToken(Template),
          useValue: templatesRepository,
        },
      ],
    }).compile();

    service = module.get(TemplatesService);
  });

  it('lists every stored template', async () => {
    const stored = [new Template(), new Template()];
    templatesRepository.find.mockResolvedValue(stored);

    await expect(service.getAllTempates()).resolves.toBe(stored);
    expect(templatesRepository.find).toHaveBeenCalledWith({});
  });

  it('returns the templates attached to an issuer', () => {
    const issuer = Object.assign(new User(), { templates: [new Template()] });

    expect(service.getAllTempatesOfIssuer(issuer)).toBe(issuer.templates);
  });
});
