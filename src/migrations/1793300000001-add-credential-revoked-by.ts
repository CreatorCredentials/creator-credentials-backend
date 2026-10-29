import { MigrationInterface, QueryRunner } from 'typeorm';

export class AddCredentialRevokedBy1793300000001 implements MigrationInterface {
  name = 'AddCredentialRevokedBy1793300000001';

  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(
      `ALTER TABLE "credential" ADD COLUMN "revoked_by_user_id" INTEGER NULL`,
    );
    await queryRunner.query(
      `ALTER TABLE "credential" ADD CONSTRAINT "FK_credential_revoked_by_user" FOREIGN KEY ("revoked_by_user_id") REFERENCES "user"("id") ON DELETE SET NULL`,
    );
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(
      `ALTER TABLE "credential" DROP CONSTRAINT "FK_credential_revoked_by_user"`,
    );
    await queryRunner.query(
      `ALTER TABLE "credential" DROP COLUMN "revoked_by_user_id"`,
    );
  }
}
