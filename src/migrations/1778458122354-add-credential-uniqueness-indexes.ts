import { MigrationInterface, QueryRunner } from "typeorm";

export class AddCredentialUniquenessIndexes1778458122354 implements MigrationInterface {
    name = 'AddCredentialUniquenessIndexes1778458122354'

    public async up(queryRunner: QueryRunner): Promise<void> {
        // EMAIL: at most one row per user (any status)
        await queryRunner.query(`
            CREATE UNIQUE INDEX IF NOT EXISTS "idx_credential_unique_email"
            ON "credential" ("user_id")
            WHERE "credential_type" = 'EMAIL'
        `);

        // DOMAIN: at most one row per user (any status)
        await queryRunner.query(`
            CREATE UNIQUE INDEX IF NOT EXISTS "idx_credential_unique_domain"
            ON "credential" ("user_id")
            WHERE "credential_type" = 'DOMAIN'
        `);

        // All other types: at most one PENDING row per user+type.
        // Multiple credentials of the same type (even from the same issuer) are
        // allowed once each pending resolves to success or is rejected.
        await queryRunner.query(`
            CREATE UNIQUE INDEX IF NOT EXISTS "idx_credential_unique_pending"
            ON "credential" ("user_id", "credential_type")
            WHERE "credential_status" = 'PENDING'
              AND "credential_type" NOT IN ('EMAIL', 'DOMAIN')
        `);
    }

    public async down(queryRunner: QueryRunner): Promise<void> {
        await queryRunner.query(`DROP INDEX IF EXISTS "idx_credential_unique_pending"`);
        await queryRunner.query(`DROP INDEX IF EXISTS "idx_credential_unique_domain"`);
        await queryRunner.query(`DROP INDEX IF EXISTS "idx_credential_unique_email"`);
    }

}
