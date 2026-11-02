import { MigrationInterface, QueryRunner } from 'typeorm';

/**
 * The Verified Creator credential is requested from an issuer and signed with
 * the issuer's certificate, like the data supplier credentials, so issuers
 * must be able to list it among the credentials they issue.
 */
export class CreatorCredentialOfferedByIssuers1793700000000
  implements MigrationInterface
{
  name = 'CreatorCredentialOfferedByIssuers1793700000000';

  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(
      `ALTER TYPE "public"."user_credentials_to_issue_enum" ADD VALUE IF NOT EXISTS 'CREATOR'`,
    );
    await queryRunner.query(
      `ALTER TYPE "public"."template_template_type_enum" ADD VALUE IF NOT EXISTS 'CREATOR'`,
    );
  }

  public async down(): Promise<void> {
    // PostgreSQL cannot drop a single enum value; the values stay.
  }
}
