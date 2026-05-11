import { Controller, Get, NotFoundException, UseGuards } from '@nestjs/common';
import { TemplatesService } from './templates.service';
import { AuthGuard } from 'src/users/guards/clerk-user.guard';
import { GetUser } from 'src/users/get-user.decorator';
import { ClerkRole, User } from 'src/users/user.entity';
import { UsersService } from 'src/users/users.service';
import { CredentialTemplateType } from 'src/shared/typings/CredentialTemplateType';
import { CredentialType } from 'src/shared/typings/CredentialType';

/** Maps each issuable CredentialType to the template type a creator requests it through. */
const CREDENTIAL_TYPE_TO_TEMPLATE_TYPE: Partial<
  Record<CredentialType, CredentialTemplateType>
> = {
  [CredentialType.Member]: CredentialTemplateType.Member,
  [CredentialType.DataSupplier]: CredentialTemplateType.ExternalKeypair,
  [CredentialType.Student]: CredentialTemplateType.Student,
};

@Controller('templates')
export class TemplatesController {
  constructor(
    private readonly templatesService: TemplatesService,
    private readonly usersService: UsersService,
  ) {}

  @UseGuards(AuthGuard)
  @Get('creator')
  async getCreatorsWithFilter(@GetUser() user: User) {
    if (user.clerkRole !== ClerkRole.Creator) {
      throw new NotFoundException('This api is only for Creator.');
    }

    const issuers = await this.usersService.getAllConnectedIssuersOfCreator(user);

    // Collect the union of all credential types offered by connected issuers,
    // then map to the corresponding template type (deduped).
    const seen = new Set<CredentialTemplateType>();
    const templates: { templateType: CredentialTemplateType }[] = [];

    for (const issuer of issuers) {
      for (const credentialType of issuer.credentialsToIssue) {
        // DataSupplier requires the issuer to have an X.509 certificate.
        // Skip it when the cert is absent so the template is never offered.
        if (
          credentialType === CredentialType.DataSupplier &&
          !issuer.externalCertPem
        ) {
          continue;
        }

        const templateType = CREDENTIAL_TYPE_TO_TEMPLATE_TYPE[credentialType];
        if (templateType && !seen.has(templateType)) {
          seen.add(templateType);
          templates.push({ templateType });
        }
      }
    }

    return { templates };
  }

  @UseGuards(AuthGuard)
  @Get('issuer')
  async getTemplatesOfIssuer(@GetUser() user: User) {
    if (user.clerkRole !== ClerkRole.Issuer) {
      throw new NotFoundException('This api is only for Issuer.');
    }

    const templates = await this.templatesService.getAllTempatesOfIssuer(user);
    return {
      templates,
    };
  }
}
