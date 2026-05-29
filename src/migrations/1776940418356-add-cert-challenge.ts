import { MigrationInterface, QueryRunner } from "typeorm";

export class AddCertChallenge1776940418356 implements MigrationInterface {
    name = 'AddCertChallenge1776940418356'

    public async up(queryRunner: QueryRunner): Promise<void> {
        await queryRunner.query(`ALTER TABLE "users_templates" DROP CONSTRAINT "FK_7adda11b1d6d21b75f67b04cf23"`);
        await queryRunner.query(`ALTER TABLE "users_templates" DROP CONSTRAINT "FK_9dd4980feb0086ab8a32eaaa10b"`);
        await queryRunner.query(`CREATE TYPE "public"."cert_challenge_status_enum" AS ENUM('initiated', 'challenge_issued', 'verified', 'failed')`);
        await queryRunner.query(`CREATE TABLE "cert_challenge" ("id" SERIAL NOT NULL, "user_id" integer NOT NULL, "cert_pem" text, "challenge_message" text, "status" "public"."cert_challenge_status_enum" NOT NULL DEFAULT 'initiated', "current_step" integer NOT NULL DEFAULT '1', "verified_at" TIMESTAMP, "created_at" TIMESTAMP NOT NULL DEFAULT now(), "updated_at" TIMESTAMP NOT NULL DEFAULT now(), CONSTRAINT "PK_2d0801814a76d1972de581fd44c" PRIMARY KEY ("id"))`);
        await queryRunner.query(`ALTER TABLE "user" ADD "external_cert_pem" text`);
        await queryRunner.query(`ALTER TABLE "user" ADD "active_signing_cert_source" character varying NOT NULL DEFAULT 'platform'`);
        await queryRunner.query(`ALTER TYPE "public"."keypair_challenge_status_enum" RENAME TO "keypair_challenge_status_enum_old"`);
        await queryRunner.query(`CREATE TYPE "public"."keypair_challenge_status_enum" AS ENUM('initiated', 'challenge_issued', 'verified', 'failed')`);
        await queryRunner.query(`ALTER TABLE "keypair_challenge" ALTER COLUMN "status" DROP DEFAULT`);
        await queryRunner.query(`ALTER TABLE "keypair_challenge" ALTER COLUMN "status" TYPE "public"."keypair_challenge_status_enum" USING "status"::"text"::"public"."keypair_challenge_status_enum"`);
        await queryRunner.query(`ALTER TABLE "keypair_challenge" ALTER COLUMN "status" SET DEFAULT 'initiated'`);
        await queryRunner.query(`DROP TYPE "public"."keypair_challenge_status_enum_old"`);
        await queryRunner.query(`ALTER TABLE "cert_challenge" ADD CONSTRAINT "FK_7d437a71e8729a296c8581997f7" FOREIGN KEY ("user_id") REFERENCES "user"("id") ON DELETE NO ACTION ON UPDATE NO ACTION`);
        await queryRunner.query(`ALTER TABLE "users_templates" ADD CONSTRAINT "FK_7adda11b1d6d21b75f67b04cf23" FOREIGN KEY ("template_id") REFERENCES "template"("id") ON DELETE CASCADE ON UPDATE CASCADE`);
        await queryRunner.query(`ALTER TABLE "users_templates" ADD CONSTRAINT "FK_9dd4980feb0086ab8a32eaaa10b" FOREIGN KEY ("user_id") REFERENCES "user"("id") ON DELETE NO ACTION ON UPDATE NO ACTION`);
    }

    public async down(queryRunner: QueryRunner): Promise<void> {
        await queryRunner.query(`ALTER TABLE "users_templates" DROP CONSTRAINT "FK_9dd4980feb0086ab8a32eaaa10b"`);
        await queryRunner.query(`ALTER TABLE "users_templates" DROP CONSTRAINT "FK_7adda11b1d6d21b75f67b04cf23"`);
        await queryRunner.query(`ALTER TABLE "cert_challenge" DROP CONSTRAINT "FK_7d437a71e8729a296c8581997f7"`);
        await queryRunner.query(`CREATE TYPE "public"."keypair_challenge_status_enum_old" AS ENUM('initiated', 'challenge_issued', 'verified', 'failed')`);
        await queryRunner.query(`ALTER TABLE "keypair_challenge" ALTER COLUMN "status" DROP DEFAULT`);
        await queryRunner.query(`ALTER TABLE "keypair_challenge" ALTER COLUMN "status" TYPE "public"."keypair_challenge_status_enum_old" USING "status"::"text"::"public"."keypair_challenge_status_enum_old"`);
        await queryRunner.query(`ALTER TABLE "keypair_challenge" ALTER COLUMN "status" SET DEFAULT 'initiated'`);
        await queryRunner.query(`DROP TYPE "public"."keypair_challenge_status_enum"`);
        await queryRunner.query(`ALTER TYPE "public"."keypair_challenge_status_enum_old" RENAME TO "keypair_challenge_status_enum"`);
        await queryRunner.query(`ALTER TABLE "user" DROP COLUMN "active_signing_cert_source"`);
        await queryRunner.query(`ALTER TABLE "user" DROP COLUMN "external_cert_pem"`);
        await queryRunner.query(`DROP TABLE "cert_challenge"`);
        await queryRunner.query(`DROP TYPE "public"."cert_challenge_status_enum"`);
        await queryRunner.query(`ALTER TABLE "users_templates" ADD CONSTRAINT "FK_9dd4980feb0086ab8a32eaaa10b" FOREIGN KEY ("user_id") REFERENCES "user"("id") ON DELETE NO ACTION ON UPDATE NO ACTION`);
        await queryRunner.query(`ALTER TABLE "users_templates" ADD CONSTRAINT "FK_7adda11b1d6d21b75f67b04cf23" FOREIGN KEY ("template_id") REFERENCES "template"("id") ON DELETE CASCADE ON UPDATE CASCADE`);
    }

}
