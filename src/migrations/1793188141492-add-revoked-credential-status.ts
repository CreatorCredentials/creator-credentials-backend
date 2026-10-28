import { MigrationInterface, QueryRunner } from 'typeorm';

export class AddRevokedCredentialStatus1793188141492
  implements MigrationInterface
{
  name = 'AddRevokedCredentialStatus1793188141492';

  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(
      `ALTER TYPE "public"."credential_credential_status_enum" ADD VALUE IF NOT EXISTS 'REVOKED'`,
    );
    await queryRunner.query(
      `ALTER TABLE "credential" ADD COLUMN "revoked_at" TIMESTAMPTZ NULL`,
    );
    await queryRunner.query(
      `ALTER TABLE "credential" ADD COLUMN "revoked_reason" VARCHAR(500) NULL`,
    );
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    // The enum cast below fails while REVOKED rows exist: delete or re-map
    // them before reverting.
    await queryRunner.query(
      `ALTER TABLE "credential" DROP COLUMN "revoked_reason"`,
    );
    await queryRunner.query(
      `ALTER TABLE "credential" DROP COLUMN "revoked_at"`,
    );
    // The partial index on credential_status is rebuilt around the type swap: its predicate pins the old type.
    await queryRunner.query(
      `DROP INDEX IF EXISTS "idx_credential_unique_pending"`,
    );
    await queryRunner.query(
      `ALTER TYPE "public"."credential_credential_status_enum" RENAME TO "credential_credential_status_enum_old"`,
    );
    await queryRunner.query(
      `CREATE TYPE "public"."credential_credential_status_enum" AS ENUM('PENDING', 'SUCCESS', 'FAILED')`,
    );
    await queryRunner.query(
      `ALTER TABLE "credential" ALTER COLUMN "credential_status" DROP DEFAULT`,
    );
    await queryRunner.query(
      `ALTER TABLE "credential" ALTER COLUMN "credential_status" TYPE "public"."credential_credential_status_enum" USING "credential_status"::"text"::"public"."credential_credential_status_enum"`,
    );
    await queryRunner.query(
      `ALTER TABLE "credential" ALTER COLUMN "credential_status" SET DEFAULT 'PENDING'`,
    );
    await queryRunner.query(
      `DROP TYPE "public"."credential_credential_status_enum_old"`,
    );
    await queryRunner.query(`
      CREATE UNIQUE INDEX IF NOT EXISTS "idx_credential_unique_pending"
      ON "credential" ("user_id", "credential_type")
      WHERE "credential_status" = 'PENDING'
        AND "credential_type" NOT IN ('EMAIL', 'DOMAIN')
    `);
  }
}
