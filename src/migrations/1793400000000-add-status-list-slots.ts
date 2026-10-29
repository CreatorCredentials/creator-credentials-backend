import { MigrationInterface, QueryRunner } from 'typeorm';

/**
 * Status list indices are drawn at random instead of taken from a sequence
 * (W3C Bitstring Status List §6.5: sequential indices reveal issuance
 * volume). The slot table records every index ever handed out so none is
 * reused (§6.7); the values the sequence already consumed are carried over.
 */
export class AddStatusListSlots1793400000000 implements MigrationInterface {
  name = 'AddStatusListSlots1793400000000';

  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(
      `CREATE TABLE "credential_status_list_slot" ("index" INTEGER PRIMARY KEY, "reserved_at" TIMESTAMPTZ NOT NULL DEFAULT now())`,
    );
    await queryRunner.query(
      `INSERT INTO "credential_status_list_slot" ("index")
       SELECT generate_series(0, GREATEST(last_value, 0) - CASE WHEN is_called THEN 0 ELSE 1 END)
       FROM "credential_status_list_index_seq"
       ON CONFLICT DO NOTHING`,
    );
    await queryRunner.query(
      `INSERT INTO "credential_status_list_slot" ("index")
       SELECT "status_list_index" FROM "credential" WHERE "status_list_index" IS NOT NULL
       ON CONFLICT DO NOTHING`,
    );
    await queryRunner.query(
      `DROP SEQUENCE IF EXISTS "credential_status_list_index_seq"`,
    );
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(
      `CREATE SEQUENCE IF NOT EXISTS "credential_status_list_index_seq" AS INTEGER MINVALUE 0 MAXVALUE 131071 START WITH 0 NO CYCLE`,
    );
    await queryRunner.query(
      `SELECT setval('credential_status_list_index_seq', COALESCE((SELECT MAX("index") FROM "credential_status_list_slot"), 0), (SELECT COUNT(*) > 0 FROM "credential_status_list_slot"))`,
    );
    await queryRunner.query(`DROP TABLE "credential_status_list_slot"`);
  }
}
