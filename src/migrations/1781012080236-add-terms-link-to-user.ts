import { MigrationInterface, QueryRunner } from "typeorm";

export class AddTermsLinkToUser1781012080236 implements MigrationInterface {
    name = 'AddTermsLinkToUser1781012080236'

    public async up(queryRunner: QueryRunner): Promise<void> {
        await queryRunner.query(
            `ALTER TABLE "user" ADD "terms_link" character varying`,
          );}

    public async down(queryRunner: QueryRunner): Promise<void> {
        await queryRunner.query(
            `ALTER TABLE "user" DROP COLUMN "terms_link"`,
          );
    }

}
