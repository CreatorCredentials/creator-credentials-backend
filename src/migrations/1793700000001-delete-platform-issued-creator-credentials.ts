import { MigrationInterface, QueryRunner } from 'typeorm';

/**
 * Between 2026-10-29 and the revision of CR-4 the platform issued
 * VerifiableCreator credentials itself when a Liccium account was linked.
 * The client decided to drop them: the credential is issued by issuers only.
 * Platform-issued rows are the ones without an issuer. Their status-list
 * indices stay reserved (indices are never reused).
 */
export class DeletePlatformIssuedCreatorCredentials1793700000001
  implements MigrationInterface
{
  name = 'DeletePlatformIssuedCreatorCredentials1793700000001';

  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(
      `DELETE FROM "credential" WHERE "credential_type" = 'CREATOR' AND "issuer_id" IS NULL`,
    );
  }

  public async down(): Promise<void> {
    // The deleted rows are not restorable; re-issuing happens through issuers.
  }
}
