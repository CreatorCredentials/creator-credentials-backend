import { NotFoundException } from '@nestjs/common';
import { CredentialTemplateType } from 'src/shared/typings/CredentialTemplateType';
import { CredentialType } from 'src/shared/typings/CredentialType';
import { ClerkRole, User } from 'src/users/user.entity';
import { UsersService } from 'src/users/users.service';
import { TemplatesController } from './templates.controller';
import { TemplatesService } from './templates.service';

function buildUser(overrides: Partial<User>): User {
  return Object.assign(new User(), overrides);
}

const creator = buildUser({ id: 20, clerkRole: ClerkRole.Creator });
const issuer = buildUser({ id: 10, clerkRole: ClerkRole.Issuer });

describe('TemplatesController', () => {
  const templatesService = { getAllTempatesOfIssuer: jest.fn() };
  const usersService = { getAllConnectedIssuersOfCreator: jest.fn() };
  const controller = new TemplatesController(
    templatesService as unknown as TemplatesService,
    usersService as unknown as UsersService,
  );

  beforeEach(() => jest.resetAllMocks());

  describe('GET templates/creator', () => {
    it('is only available to creators', async () => {
      await expect(controller.getCreatorsWithFilter(issuer)).rejects.toThrow(
        NotFoundException,
      );
      expect(
        usersService.getAllConnectedIssuersOfCreator,
      ).not.toHaveBeenCalled();
    });

    it('offers each template type once across the connected issuers', async () => {
      usersService.getAllConnectedIssuersOfCreator.mockResolvedValue([
        buildUser({
          id: 11,
          credentialsToIssue: [CredentialType.Member, CredentialType.Student],
        }),
        buildUser({
          id: 12,
          credentialsToIssue: [CredentialType.Member, CredentialType.EMail],
        }),
      ]);

      await expect(controller.getCreatorsWithFilter(creator)).resolves.toEqual({
        templates: [
          { templateType: CredentialTemplateType.Member },
          { templateType: CredentialTemplateType.Student },
        ],
      });
    });

    it('offers data supplier templates only from issuers holding a certificate', async () => {
      usersService.getAllConnectedIssuersOfCreator.mockResolvedValue([
        buildUser({
          id: 11,
          credentialsToIssue: [CredentialType.DataSupplier],
        }),
        buildUser({
          id: 12,
          credentialsToIssue: [CredentialType.LicciumDataSupplier],
          externalCertPem: '-----BEGIN CERTIFICATE-----',
        }),
      ]);

      await expect(controller.getCreatorsWithFilter(creator)).resolves.toEqual({
        templates: [
          { templateType: CredentialTemplateType.LicciumExternalKeypair },
        ],
      });
    });
  });

  describe('GET templates/issuer', () => {
    it('is only available to issuers', async () => {
      await expect(controller.getTemplatesOfIssuer(creator)).rejects.toThrow(
        NotFoundException,
      );
      expect(templatesService.getAllTempatesOfIssuer).not.toHaveBeenCalled();
    });

    it('returns the templates of the issuer', async () => {
      templatesService.getAllTempatesOfIssuer.mockResolvedValue(['t1']);

      await expect(controller.getTemplatesOfIssuer(issuer)).resolves.toEqual({
        templates: ['t1'],
      });
      expect(templatesService.getAllTempatesOfIssuer).toHaveBeenCalledWith(
        issuer,
      );
    });
  });
});
