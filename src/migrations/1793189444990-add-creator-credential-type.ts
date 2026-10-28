import { MigrationInterface, QueryRunner } from 'typeorm';

/**
 * Adds the CREATOR credential type. The unique index that uses the new value
 * lives in the next migration: PostgreSQL refuses to use an enum value inside
 * the transaction that added it, so the two must commit separately
 * (migrationsTransactionMode 'each').
 */
export class AddCreatorCredentialType1793189444990
  implements MigrationInterface
{
  name = 'AddCreatorCredentialType1793189444990';

  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(
      `ALTER TYPE "public"."credential_credential_type_enum" ADD VALUE IF NOT EXISTS 'CREATOR'`,
    );
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    // The enum cast below fails while CREATOR rows exist: delete them first.
    // The partial indexes on credential_type are rebuilt around the type swap: their predicates pin the old type.
    await queryRunner.query(
      `DROP INDEX IF EXISTS "idx_credential_unique_email"`,
    );
    await queryRunner.query(
      `DROP INDEX IF EXISTS "idx_credential_unique_domain"`,
    );
    await queryRunner.query(
      `DROP INDEX IF EXISTS "idx_credential_unique_pending"`,
    );
    await queryRunner.query(
      `ALTER TYPE "public"."credential_credential_type_enum" RENAME TO "credential_credential_type_enum_old"`,
    );
    await queryRunner.query(
      `CREATE TYPE "public"."credential_credential_type_enum" AS ENUM('EMAIL', 'WALLET', 'MEMBER', 'DATASUPPLIER', 'STUDENT', 'DOMAIN', 'DID_WEB', 'CONNECT', 'EXTERNAL_KEYPAIR_VERIFICATION', 'LICCIUM_DATASUPPLIER')`,
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
    await queryRunner.query(`
      CREATE UNIQUE INDEX IF NOT EXISTS "idx_credential_unique_email"
      ON "credential" ("user_id")
      WHERE "credential_type" = 'EMAIL'
    `);
    await queryRunner.query(`
      CREATE UNIQUE INDEX IF NOT EXISTS "idx_credential_unique_domain"
      ON "credential" ("user_id")
      WHERE "credential_type" = 'DOMAIN'
    `);
    await queryRunner.query(`
      CREATE UNIQUE INDEX IF NOT EXISTS "idx_credential_unique_pending"
      ON "credential" ("user_id", "credential_type")
      WHERE "credential_status" = 'PENDING'
        AND "credential_type" NOT IN ('EMAIL', 'DOMAIN')
    `);
  }
}
