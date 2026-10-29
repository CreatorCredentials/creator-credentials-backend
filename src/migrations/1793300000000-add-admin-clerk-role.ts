import { MigrationInterface, QueryRunner } from 'typeorm';

export class AddAdminClerkRole1793300000000 implements MigrationInterface {
  name = 'AddAdminClerkRole1793300000000';

  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(
      `ALTER TYPE "public"."user_clerk_role_enum" ADD VALUE IF NOT EXISTS 'admin'`,
    );
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    // The enum cast below fails while admin rows exist: delete or re-map
    // them before reverting.
    await queryRunner.query(
      `ALTER TYPE "public"."user_clerk_role_enum" RENAME TO "user_clerk_role_enum_old"`,
    );
    await queryRunner.query(
      `CREATE TYPE "public"."user_clerk_role_enum" AS ENUM('issuer', 'creator')`,
    );
    await queryRunner.query(
      `ALTER TABLE "user" ALTER COLUMN "clerk_role" DROP DEFAULT`,
    );
    await queryRunner.query(
      `ALTER TABLE "user" ALTER COLUMN "clerk_role" TYPE "public"."user_clerk_role_enum" USING "clerk_role"::"text"::"public"."user_clerk_role_enum"`,
    );
    await queryRunner.query(
      `ALTER TABLE "user" ALTER COLUMN "clerk_role" SET DEFAULT 'creator'`,
    );
    await queryRunner.query(`DROP TYPE "public"."user_clerk_role_enum_old"`);
  }
}
