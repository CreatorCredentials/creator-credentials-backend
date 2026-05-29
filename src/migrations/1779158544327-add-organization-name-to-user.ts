import { MigrationInterface, QueryRunner } from 'typeorm';

export class AddOrganizationNameToUser1779158544327
  implements MigrationInterface
{
  name = 'AddOrganizationNameToUser1779158544327';

  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(
      `ALTER TABLE "user" ADD "organization_name" character varying`,
    );
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(
      `ALTER TABLE "user" DROP COLUMN "organization_name"`,
    );
  }
}
