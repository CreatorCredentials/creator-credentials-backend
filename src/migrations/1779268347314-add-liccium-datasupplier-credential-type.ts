import { MigrationInterface, QueryRunner } from 'typeorm';

export class AddLicciumDatasupplierCredentialType1779268347314
  implements MigrationInterface
{
  name = 'AddLicciumDatasupplierCredentialType1779268347314';

  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(
      `ALTER TYPE "public"."credential_credential_type_enum" ADD VALUE IF NOT EXISTS 'LICCIUM_DATASUPPLIER'`,
    );
    await queryRunner.query(
      `ALTER TYPE "public"."user_credentials_to_issue_enum" ADD VALUE IF NOT EXISTS 'LICCIUM_DATASUPPLIER'`,
    );
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(
      `ALTER TYPE "public"."credential_credential_type_enum" RENAME TO "credential_credential_type_enum_old"`,
    );
    await queryRunner.query(
      `CREATE TYPE "public"."credential_credential_type_enum" AS ENUM('EMAIL', 'WALLET', 'MEMBER', 'DATASUPPLIER', 'STUDENT', 'DOMAIN', 'DID_WEB', 'CONNECT', 'EXTERNAL_KEYPAIR_VERIFICATION')`,
    );
    await queryRunner.query(
      `ALTER TABLE "credential" ALTER COLUMN "credential_type" DROP DEFAULT`,
    );
    await queryRunner.query(
      `ALTER TABLE "credential" ALTER COLUMN "credential_type" TYPE "public"."credential_credential_type_enum" USING "credential_type"::"text"::"public"."credential_credential_type_enum"`,
    );
    await queryRunner.query(
      `ALTER TABLE "credential" ALTER COLUMN "credential_type" SET DEFAULT 'EMAIL'`,
    );
    await queryRunner.query(
      `DROP TYPE "public"."credential_credential_type_enum_old"`,
    );
    await queryRunner.query(
      `ALTER TYPE "public"."user_credentials_to_issue_enum" RENAME TO "user_credentials_to_issue_enum_old"`,
    );
    await queryRunner.query(
      `CREATE TYPE "public"."user_credentials_to_issue_enum" AS ENUM('EMAIL', 'WALLET', 'MEMBER', 'DATASUPPLIER', 'STUDENT', 'DOMAIN', 'DID_WEB', 'CONNECT', 'EXTERNAL_KEYPAIR_VERIFICATION')`,
    );
    await queryRunner.query(
      `ALTER TABLE "user" ALTER COLUMN "credentials_to_issue" DROP DEFAULT`,
    );
    await queryRunner.query(
      `ALTER TABLE "user" ALTER COLUMN "credentials_to_issue" TYPE "public"."user_credentials_to_issue_enum"[] USING "credentials_to_issue"::"text"::"public"."user_credentials_to_issue_enum"[]`,
    );
    await queryRunner.query(
      `ALTER TABLE "user" ALTER COLUMN "credentials_to_issue" SET DEFAULT '{}'`,
    );
    await queryRunner.query(
      `DROP TYPE "public"."user_credentials_to_issue_enum_old"`,
    );
  }
}
