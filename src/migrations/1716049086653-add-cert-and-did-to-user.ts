import { MigrationInterface, QueryRunner } from 'typeorm';

export class AddCertAndDidToUser1716049086653 implements MigrationInterface {
  name = 'AddCertAndDidToUser1716049086653';

  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(
      `ALTER TABLE "user" ADD "certificate_509_buffer" bytea`,
    );
    await queryRunner.query(
      `ALTER TABLE "user" ADD "certificate_private_key" bytea`,
    );
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(
      `ALTER TABLE "user" DROP COLUMN "certificate_private_key"`,
    );
    await queryRunner.query(
      `ALTER TABLE "user" DROP COLUMN "certificate_509_buffer"`,
    );
  }
}
