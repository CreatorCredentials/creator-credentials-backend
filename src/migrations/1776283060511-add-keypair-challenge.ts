import { MigrationInterface, QueryRunner } from "typeorm";

export class AddKeypairChallenge1776283060511 implements MigrationInterface {
    name = 'AddKeypairChallenge1776283060511'

    public async up(queryRunner: QueryRunner): Promise<void> {
        await queryRunner.query(`ALTER TABLE "users_templates" DROP CONSTRAINT "FK_7adda11b1d6d21b75f67b04cf23"`);
        await queryRunner.query(`ALTER TABLE "users_templates" DROP CONSTRAINT "FK_9dd4980feb0086ab8a32eaaa10b"`);
        await queryRunner.query(`CREATE TYPE "public"."keypair_challenge_status_enum" AS ENUM('initiated', 'challenge_issued', 'verified', 'failed')`);
        await queryRunner.query(`CREATE TABLE "keypair_challenge" ("id" SERIAL NOT NULL, "user_id" integer NOT NULL, "public_key_pem" text, "derived_did_key" text, "challenge_message" text, "status" "public"."keypair_challenge_status_enum" NOT NULL DEFAULT 'initiated', "current_step" integer NOT NULL DEFAULT '1', "verified_at" TIMESTAMP, "created_at" TIMESTAMP NOT NULL DEFAULT now(), "updated_at" TIMESTAMP NOT NULL DEFAULT now(), CONSTRAINT "PK_f472aa0fdc520876de40f245cc6" PRIMARY KEY ("id"))`);
        await queryRunner.query(`ALTER TABLE "user" ADD "external_did_key" character varying`);
        await queryRunner.query(`ALTER TABLE "user" ADD CONSTRAINT "UQ_6e31b25f6127842e11abea55e14" UNIQUE ("external_did_key")`);
        await queryRunner.query(`ALTER TABLE "user" ADD "external_public_key_pem" text`);
        await queryRunner.query(`ALTER TABLE "user" ADD "active_did_key_source" character varying NOT NULL DEFAULT 'platform'`);
        await queryRunner.query(`ALTER TABLE "keypair_challenge" ADD CONSTRAINT "FK_9de1e9c1de36c2f6d73167dc83b" FOREIGN KEY ("user_id") REFERENCES "user"("id") ON DELETE NO ACTION ON UPDATE NO ACTION`);
        await queryRunner.query(`ALTER TABLE "users_templates" ADD CONSTRAINT "FK_7adda11b1d6d21b75f67b04cf23" FOREIGN KEY ("template_id") REFERENCES "template"("id") ON DELETE CASCADE ON UPDATE CASCADE`);
        await queryRunner.query(`ALTER TABLE "users_templates" ADD CONSTRAINT "FK_9dd4980feb0086ab8a32eaaa10b" FOREIGN KEY ("user_id") REFERENCES "user"("id") ON DELETE NO ACTION ON UPDATE NO ACTION`);
    }

    public async down(queryRunner: QueryRunner): Promise<void> {
        await queryRunner.query(`ALTER TABLE "users_templates" DROP CONSTRAINT "FK_9dd4980feb0086ab8a32eaaa10b"`);
        await queryRunner.query(`ALTER TABLE "users_templates" DROP CONSTRAINT "FK_7adda11b1d6d21b75f67b04cf23"`);
        await queryRunner.query(`ALTER TABLE "keypair_challenge" DROP CONSTRAINT "FK_9de1e9c1de36c2f6d73167dc83b"`);
        await queryRunner.query(`ALTER TABLE "user" DROP COLUMN "active_did_key_source"`);
        await queryRunner.query(`ALTER TABLE "user" DROP COLUMN "external_public_key_pem"`);
        await queryRunner.query(`ALTER TABLE "user" DROP CONSTRAINT "UQ_6e31b25f6127842e11abea55e14"`);
        await queryRunner.query(`ALTER TABLE "user" DROP COLUMN "external_did_key"`);
        await queryRunner.query(`DROP TABLE "keypair_challenge"`);
        await queryRunner.query(`DROP TYPE "public"."keypair_challenge_status_enum"`);
        await queryRunner.query(`ALTER TABLE "users_templates" ADD CONSTRAINT "FK_9dd4980feb0086ab8a32eaaa10b" FOREIGN KEY ("user_id") REFERENCES "user"("id") ON DELETE NO ACTION ON UPDATE NO ACTION`);
        await queryRunner.query(`ALTER TABLE "users_templates" ADD CONSTRAINT "FK_7adda11b1d6d21b75f67b04cf23" FOREIGN KEY ("template_id") REFERENCES "template"("id") ON DELETE CASCADE ON UPDATE CASCADE`);
    }

}
