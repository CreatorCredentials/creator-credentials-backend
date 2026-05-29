import { MigrationInterface, QueryRunner } from 'typeorm';

export class AddExternalKeypairVerificationCredentialType1778958563313
  implements MigrationInterface
{
  name = 'AddExternalKeypairVerificationCredentialType1778958563313';

  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(
      `ALTER TYPE "public"."credential_credential_type_enum" ADD VALUE IF NOT EXISTS 'EXTERNAL_KEYPAIR_VERIFICATION'`,
    );
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(
      `ALTER TYPE "public"."credential_credential_type_enum" RENAME TO "credential_credential_type_enum_old"`,
    );
    await queryRunner.query(
      `CREATE TYPE "public"."credential_credential_type_enum" AS ENUM('EMAIL', 'WALLET', 'MEMBER', 'DATASUPPLIER', 'STUDENT', 'DOMAIN', 'DID_WEB', 'CONNECT')`,
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
  }
}
