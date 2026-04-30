import { MigrationInterface, QueryRunner } from "typeorm";

export class CertChallengeUpdate1777560023071 implements MigrationInterface {
    name = 'CertChallengeUpdate1777560023071'

    public async up(queryRunner: QueryRunner): Promise<void> {
        await queryRunner.query(`ALTER TABLE "users_templates" DROP CONSTRAINT "FK_7adda11b1d6d21b75f67b04cf23"`);
        await queryRunner.query(`ALTER TABLE "users_templates" DROP CONSTRAINT "FK_9dd4980feb0086ab8a32eaaa10b"`);
        await queryRunner.query(`ALTER TABLE "cert_challenge" ADD "cert_fingerprint" character varying(64)`);
        await queryRunner.query(`ALTER TABLE "cert_challenge" ADD "expires_at" TIMESTAMP`);
        await queryRunner.query(`ALTER TYPE "public"."keypair_challenge_status_enum" RENAME TO "keypair_challenge_status_enum_old"`);
        await queryRunner.query(`CREATE TYPE "public"."keypair_challenge_status_enum" AS ENUM('initiated', 'challenge_issued', 'verified', 'failed')`);
        await queryRunner.query(`ALTER TABLE "keypair_challenge" ALTER COLUMN "status" DROP DEFAULT`);
        await queryRunner.query(`ALTER TABLE "keypair_challenge" ALTER COLUMN "status" TYPE "public"."keypair_challenge_status_enum" USING "status"::"text"::"public"."keypair_challenge_status_enum"`);
        await queryRunner.query(`ALTER TABLE "keypair_challenge" ALTER COLUMN "status" SET DEFAULT 'initiated'`);
        await queryRunner.query(`DROP TYPE "public"."keypair_challenge_status_enum_old"`);
        await queryRunner.query(`ALTER TYPE "public"."cert_challenge_status_enum" RENAME TO "cert_challenge_status_enum_old"`);
        await queryRunner.query(`CREATE TYPE "public"."cert_challenge_status_enum" AS ENUM('initiated', 'challenge_issued', 'verified', 'failed')`);
        await queryRunner.query(`ALTER TABLE "cert_challenge" ALTER COLUMN "status" DROP DEFAULT`);
        await queryRunner.query(`ALTER TABLE "cert_challenge" ALTER COLUMN "status" TYPE "public"."cert_challenge_status_enum" USING "status"::"text"::"public"."cert_challenge_status_enum"`);
        await queryRunner.query(`ALTER TABLE "cert_challenge" ALTER COLUMN "status" SET DEFAULT 'initiated'`);
        await queryRunner.query(`DROP TYPE "public"."cert_challenge_status_enum_old"`);
        await queryRunner.query(`ALTER TABLE "users_templates" ADD CONSTRAINT "FK_9dd4980feb0086ab8a32eaaa10b" FOREIGN KEY ("user_id") REFERENCES "user"("id") ON DELETE CASCADE ON UPDATE CASCADE`);
        await queryRunner.query(`ALTER TABLE "users_templates" ADD CONSTRAINT "FK_7adda11b1d6d21b75f67b04cf23" FOREIGN KEY ("template_id") REFERENCES "template"("id") ON DELETE NO ACTION ON UPDATE NO ACTION`);
    }

    public async down(queryRunner: QueryRunner): Promise<void> {
        await queryRunner.query(`ALTER TABLE "users_templates" DROP CONSTRAINT "FK_7adda11b1d6d21b75f67b04cf23"`);
        await queryRunner.query(`ALTER TABLE "users_templates" DROP CONSTRAINT "FK_9dd4980feb0086ab8a32eaaa10b"`);
        await queryRunner.query(`CREATE TYPE "public"."cert_challenge_status_enum_old" AS ENUM('initiated', 'challenge_issued', 'verified', 'failed')`);
        await queryRunner.query(`ALTER TABLE "cert_challenge" ALTER COLUMN "status" DROP DEFAULT`);
        await queryRunner.query(`ALTER TABLE "cert_challenge" ALTER COLUMN "status" TYPE "public"."cert_challenge_status_enum_old" USING "status"::"text"::"public"."cert_challenge_status_enum_old"`);
        await queryRunner.query(`ALTER TABLE "cert_challenge" ALTER COLUMN "status" SET DEFAULT 'initiated'`);
        await queryRunner.query(`DROP TYPE "public"."cert_challenge_status_enum"`);
        await queryRunner.query(`ALTER TYPE "public"."cert_challenge_status_enum_old" RENAME TO "cert_challenge_status_enum"`);
        await queryRunner.query(`CREATE TYPE "public"."keypair_challenge_status_enum_old" AS ENUM('initiated', 'challenge_issued', 'verified', 'failed')`);
        await queryRunner.query(`ALTER TABLE "keypair_challenge" ALTER COLUMN "status" DROP DEFAULT`);
        await queryRunner.query(`ALTER TABLE "keypair_challenge" ALTER COLUMN "status" TYPE "public"."keypair_challenge_status_enum_old" USING "status"::"text"::"public"."keypair_challenge_status_enum_old"`);
        await queryRunner.query(`ALTER TABLE "keypair_challenge" ALTER COLUMN "status" SET DEFAULT 'initiated'`);
        await queryRunner.query(`DROP TYPE "public"."keypair_challenge_status_enum"`);
        await queryRunner.query(`ALTER TYPE "public"."keypair_challenge_status_enum_old" RENAME TO "keypair_challenge_status_enum"`);
        await queryRunner.query(`ALTER TABLE "cert_challenge" DROP COLUMN "expires_at"`);
        await queryRunner.query(`ALTER TABLE "cert_challenge" DROP COLUMN "cert_fingerprint"`);
        await queryRunner.query(`ALTER TABLE "users_templates" ADD CONSTRAINT "FK_9dd4980feb0086ab8a32eaaa10b" FOREIGN KEY ("user_id") REFERENCES "user"("id") ON DELETE NO ACTION ON UPDATE NO ACTION`);
        await queryRunner.query(`ALTER TABLE "users_templates" ADD CONSTRAINT "FK_7adda11b1d6d21b75f67b04cf23" FOREIGN KEY ("template_id") REFERENCES "template"("id") ON DELETE CASCADE ON UPDATE CASCADE`);
    }

}
