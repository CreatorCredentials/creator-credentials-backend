import { MigrationInterface, QueryRunner } from 'typeorm';

/**
 * One Bitstring Status List of 131 072 entries per environment; every
 * credential issued from now on takes the next free index from the sequence.
 */
export class AddCredentialStatusListIndex1793300000002
  implements MigrationInterface
{
  name = 'AddCredentialStatusListIndex1793300000002';

  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(
      `CREATE SEQUENCE IF NOT EXISTS "credential_status_list_index_seq" AS INTEGER MINVALUE 0 MAXVALUE 131071 START WITH 0 NO CYCLE`,
    );
    await queryRunner.query(
      `ALTER TABLE "credential" ADD COLUMN "status_list_index" INTEGER NULL`,
    );
    await queryRunner.query(
      `ALTER TABLE "credential" ADD CONSTRAINT "UQ_credential_status_list_index" UNIQUE ("status_list_index")`,
    );
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(
      `ALTER TABLE "credential" DROP CONSTRAINT "UQ_credential_status_list_index"`,
    );
    await queryRunner.query(
      `ALTER TABLE "credential" DROP COLUMN "status_list_index"`,
    );
    await queryRunner.query(
      `DROP SEQUENCE IF EXISTS "credential_status_list_index_seq"`,
    );
  }
}
