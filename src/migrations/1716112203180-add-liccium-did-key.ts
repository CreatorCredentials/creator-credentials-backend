import { MigrationInterface, QueryRunner } from "typeorm";

export class AddLicciumDidKey1716112203180 implements MigrationInterface {
    name = 'AddLicciumDidKey1716112203180'

    public async up(queryRunner: QueryRunner): Promise<void> {
        await queryRunner.query(`ALTER TABLE "users_templates" DROP CONSTRAINT "FK_7adda11b1d6d21b75f67b04cf23"`);
        await queryRunner.query(`ALTER TABLE "users_templates" DROP CONSTRAINT "FK_9dd4980feb0086ab8a32eaaa10b"`);
        await queryRunner.query(`ALTER TABLE "user" ADD "liccium_did_key" character varying`);
        await queryRunner.query(`ALTER TABLE "user" ADD CONSTRAINT "UQ_5469cbd56a9e4baa8f636c07f3e" UNIQUE ("liccium_did_key")`);
        await queryRunner.query(`ALTER TABLE "users_templates" ADD CONSTRAINT "FK_7adda11b1d6d21b75f67b04cf23" FOREIGN KEY ("template_id") REFERENCES "template"("id") ON DELETE CASCADE ON UPDATE CASCADE`);
        await queryRunner.query(`ALTER TABLE "users_templates" ADD CONSTRAINT "FK_9dd4980feb0086ab8a32eaaa10b" FOREIGN KEY ("user_id") REFERENCES "user"("id") ON DELETE NO ACTION ON UPDATE NO ACTION`);
    }

    public async down(queryRunner: QueryRunner): Promise<void> {
        await queryRunner.query(`ALTER TABLE "users_templates" DROP CONSTRAINT "FK_9dd4980feb0086ab8a32eaaa10b"`);
        await queryRunner.query(`ALTER TABLE "users_templates" DROP CONSTRAINT "FK_7adda11b1d6d21b75f67b04cf23"`);
        await queryRunner.query(`ALTER TABLE "user" DROP CONSTRAINT "UQ_5469cbd56a9e4baa8f636c07f3e"`);
        await queryRunner.query(`ALTER TABLE "user" DROP COLUMN "liccium_did_key"`);
        await queryRunner.query(`ALTER TABLE "users_templates" ADD CONSTRAINT "FK_9dd4980feb0086ab8a32eaaa10b" FOREIGN KEY ("user_id") REFERENCES "user"("id") ON DELETE NO ACTION ON UPDATE NO ACTION`);
        await queryRunner.query(`ALTER TABLE "users_templates" ADD CONSTRAINT "FK_7adda11b1d6d21b75f67b04cf23" FOREIGN KEY ("template_id") REFERENCES "template"("id") ON DELETE CASCADE ON UPDATE CASCADE`);
    }

}
