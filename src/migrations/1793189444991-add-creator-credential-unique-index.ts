import { MigrationInterface, QueryRunner } from 'typeorm';

/** One CREATOR credential per user. Separate from the enum change on purpose, see the previous migration. */
export class AddCreatorCredentialUniqueIndex1793189444991
  implements MigrationInterface
{
  name = 'AddCreatorCredentialUniqueIndex1793189444991';

  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`
      CREATE UNIQUE INDEX IF NOT EXISTS "idx_credential_unique_creator"
      ON "credential" ("user_id")
      WHERE "credential_type" = 'CREATOR'
    `);
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(
      `DROP INDEX IF EXISTS "idx_credential_unique_creator"`,
    );
  }
}
