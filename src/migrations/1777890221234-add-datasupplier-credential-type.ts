import { MigrationInterface, QueryRunner } from "typeorm";

export class AddDatasupplierCredentialType1777890221234 implements MigrationInterface {
    name = 'AddDatasupplierCredentialType1777890221234'

    public async up(queryRunner: QueryRunner): Promise<void> {
        await queryRunner.query(`ALTER TABLE "users_templates" DROP CONSTRAINT "FK_7adda11b1d6d21b75f67b04cf23"`);
        await queryRunner.query(`ALTER TABLE "users_templates" DROP CONSTRAINT "FK_9dd4980feb0086ab8a32eaaa10b"`);
        await queryRunner.query(`ALTER TYPE "public"."credential_credential_type_enum" RENAME TO "credential_credential_type_enum_old"`);
        await queryRunner.query(`CREATE TYPE "public"."credential_credential_type_enum" AS ENUM('EMAIL', 'WALLET', 'MEMBER', 'DATASUPPLIER', 'STUDENT', 'DOMAIN', 'DID_WEB', 'CONNECT')`);
        await queryRunner.query(`ALTER TABLE "credential" ALTER COLUMN "credential_type" DROP DEFAULT`);
        await queryRunner.query(`ALTER TABLE "credential" ALTER COLUMN "credential_type" TYPE "public"."credential_credential_type_enum" USING "credential_type"::"text"::"public"."credential_credential_type_enum"`);
        await queryRunner.query(`ALTER TABLE "credential" ALTER COLUMN "credential_type" SET DEFAULT 'EMAIL'`);
        await queryRunner.query(`DROP TYPE "public"."credential_credential_type_enum_old"`);
        await queryRunner.query(`ALTER TYPE "public"."cert_challenge_status_enum" RENAME TO "cert_challenge_status_enum_old"`);
        await queryRunner.query(`CREATE TYPE "public"."cert_challenge_status_enum" AS ENUM('initiated', 'challenge_issued', 'verified', 'failed')`);
        await queryRunner.query(`ALTER TABLE "cert_challenge" ALTER COLUMN "status" DROP DEFAULT`);
        await queryRunner.query(`ALTER TABLE "cert_challenge" ALTER COLUMN "status" TYPE "public"."cert_challenge_status_enum" USING "status"::"text"::"public"."cert_challenge_status_enum"`);
        await queryRunner.query(`ALTER TABLE "cert_challenge" ALTER COLUMN "status" SET DEFAULT 'initiated'`);
        await queryRunner.query(`DROP TYPE "public"."cert_challenge_status_enum_old"`);
        await queryRunner.query(`ALTER TYPE "public"."user_credentials_to_issue_enum" RENAME TO "user_credentials_to_issue_enum_old"`);
        await queryRunner.query(`CREATE TYPE "public"."user_credentials_to_issue_enum" AS ENUM('EMAIL', 'WALLET', 'MEMBER', 'DATASUPPLIER', 'STUDENT', 'DOMAIN', 'DID_WEB', 'CONNECT')`);
        await queryRunner.query(`ALTER TABLE "user" ALTER COLUMN "credentials_to_issue" DROP DEFAULT`);
        await queryRunner.query(`ALTER TABLE "user" ALTER COLUMN "credentials_to_issue" TYPE "public"."user_credentials_to_issue_enum"[] USING "credentials_to_issue"::"text"::"public"."user_credentials_to_issue_enum"[]`);
        await queryRunner.query(`ALTER TABLE "user" ALTER COLUMN "credentials_to_issue" SET DEFAULT '{}'`);
        await queryRunner.query(`DROP TYPE "public"."user_credentials_to_issue_enum_old"`);
        await queryRunner.query(`ALTER TYPE "public"."keypair_challenge_status_enum" RENAME TO "keypair_challenge_status_enum_old"`);
        await queryRunner.query(`CREATE TYPE "public"."keypair_challenge_status_enum" AS ENUM('initiated', 'challenge_issued', 'verified', 'consumed', 'failed')`);
        await queryRunner.query(`ALTER TABLE "keypair_challenge" ALTER COLUMN "status" DROP DEFAULT`);
        await queryRunner.query(`ALTER TABLE "keypair_challenge" ALTER COLUMN "status" TYPE "public"."keypair_challenge_status_enum" USING "status"::"text"::"public"."keypair_challenge_status_enum"`);
        await queryRunner.query(`ALTER TABLE "keypair_challenge" ALTER COLUMN "status" SET DEFAULT 'initiated'`);
        await queryRunner.query(`DROP TYPE "public"."keypair_challenge_status_enum_old"`);
        await queryRunner.query(`ALTER TABLE "users_templates" ADD CONSTRAINT "FK_7adda11b1d6d21b75f67b04cf23" FOREIGN KEY ("template_id") REFERENCES "template"("id") ON DELETE CASCADE ON UPDATE CASCADE`);
        await queryRunner.query(`ALTER TABLE "users_templates" ADD CONSTRAINT "FK_9dd4980feb0086ab8a32eaaa10b" FOREIGN KEY ("user_id") REFERENCES "user"("id") ON DELETE NO ACTION ON UPDATE NO ACTION`);
    }

    public async down(queryRunner: QueryRunner): Promise<void> {
        await queryRunner.query(`ALTER TABLE "users_templates" DROP CONSTRAINT "FK_9dd4980feb0086ab8a32eaaa10b"`);
        await queryRunner.query(`ALTER TABLE "users_templates" DROP CONSTRAINT "FK_7adda11b1d6d21b75f67b04cf23"`);
        await queryRunner.query(`CREATE TYPE "public"."keypair_challenge_status_enum_old" AS ENUM('initiated', 'challenge_issued', 'verified', 'consumed', 'failed')`);
        await queryRunner.query(`ALTER TABLE "keypair_challenge" ALTER COLUMN "status" DROP DEFAULT`);
        await queryRunner.query(`ALTER TABLE "keypair_challenge" ALTER COLUMN "status" TYPE "public"."keypair_challenge_status_enum_old" USING "status"::"text"::"public"."keypair_challenge_status_enum_old"`);
        await queryRunner.query(`ALTER TABLE "keypair_challenge" ALTER COLUMN "status" SET DEFAULT 'initiated'`);
        await queryRunner.query(`DROP TYPE "public"."keypair_challenge_status_enum"`);
        await queryRunner.query(`ALTER TYPE "public"."keypair_challenge_status_enum_old" RENAME TO "keypair_challenge_status_enum"`);
        await queryRunner.query(`CREATE TYPE "public"."user_credentials_to_issue_enum_old" AS ENUM('EMAIL', 'WALLET', 'MEMBER', 'STUDENT', 'DOMAIN', 'DID_WEB', 'CONNECT')`);
        await queryRunner.query(`ALTER TABLE "user" ALTER COLUMN "credentials_to_issue" DROP DEFAULT`);
        await queryRunner.query(`ALTER TABLE "user" ALTER COLUMN "credentials_to_issue" TYPE "public"."user_credentials_to_issue_enum_old"[] USING "credentials_to_issue"::"text"::"public"."user_credentials_to_issue_enum_old"[]`);
        await queryRunner.query(`ALTER TABLE "user" ALTER COLUMN "credentials_to_issue" SET DEFAULT '{}'`);
        await queryRunner.query(`DROP TYPE "public"."user_credentials_to_issue_enum"`);
        await queryRunner.query(`ALTER TYPE "public"."user_credentials_to_issue_enum_old" RENAME TO "user_credentials_to_issue_enum"`);
        await queryRunner.query(`CREATE TYPE "public"."cert_challenge_status_enum_old" AS ENUM('initiated', 'challenge_issued', 'verified', 'failed')`);
        await queryRunner.query(`ALTER TABLE "cert_challenge" ALTER COLUMN "status" DROP DEFAULT`);
        await queryRunner.query(`ALTER TABLE "cert_challenge" ALTER COLUMN "status" TYPE "public"."cert_challenge_status_enum_old" USING "status"::"text"::"public"."cert_challenge_status_enum_old"`);
        await queryRunner.query(`ALTER TABLE "cert_challenge" ALTER COLUMN "status" SET DEFAULT 'initiated'`);
        await queryRunner.query(`DROP TYPE "public"."cert_challenge_status_enum"`);
        await queryRunner.query(`ALTER TYPE "public"."cert_challenge_status_enum_old" RENAME TO "cert_challenge_status_enum"`);
        await queryRunner.query(`CREATE TYPE "public"."credential_credential_type_enum_old" AS ENUM('EMAIL', 'WALLET', 'MEMBER', 'STUDENT', 'DOMAIN', 'DID_WEB', 'CONNECT')`);
        await queryRunner.query(`ALTER TABLE "credential" ALTER COLUMN "credential_type" DROP DEFAULT`);
        await queryRunner.query(`ALTER TABLE "credential" ALTER COLUMN "credential_type" TYPE "public"."credential_credential_type_enum_old" USING "credential_type"::"text"::"public"."credential_credential_type_enum_old"`);
        await queryRunner.query(`ALTER TABLE "credential" ALTER COLUMN "credential_type" SET DEFAULT 'EMAIL'`);
        await queryRunner.query(`DROP TYPE "public"."credential_credential_type_enum"`);
        await queryRunner.query(`ALTER TYPE "public"."credential_credential_type_enum_old" RENAME TO "credential_credential_type_enum"`);
        await queryRunner.query(`ALTER TABLE "users_templates" ADD CONSTRAINT "FK_9dd4980feb0086ab8a32eaaa10b" FOREIGN KEY ("user_id") REFERENCES "user"("id") ON DELETE NO ACTION ON UPDATE NO ACTION`);
        await queryRunner.query(`ALTER TABLE "users_templates" ADD CONSTRAINT "FK_7adda11b1d6d21b75f67b04cf23" FOREIGN KEY ("template_id") REFERENCES "template"("id") ON DELETE CASCADE ON UPDATE CASCADE`);
    }

}
