 # creator-credentials-backend

NestJS API for the Creator Credentials platform: Clerk-authenticated issuer/creator identities, per-user X.509 certificates and did:key, and the Verifiable Credential issuance engine (email / domain / did:web / membership / data-supplier), plus eIDAS QSeal/QSig external-certificate import and challenge verification.

## Stack

- **NestJS 10** (URI versioning, all routes under `/v1` except version-neutral `health` + `/`)
- **TypeORM 0.3 + PostgreSQL** (`synchronize: false`, `migrationsRun: true` – migrations auto-run on boot)
- **Clerk** – `@clerk/express` middleware (`ClerkExpressWithAuth`) + `@clerk/backend`; `svix` for webhook signature verification
- **@peculiar/x509** + `@peculiar/webcrypto` – X.509 cert parsing/building; `openssl` (shelled out) mints the per-user self-signed cert
- **jose** (EC P-256 / ES256 VC signing) + **jsonwebtoken** (RS256 `x5c` platform signer, and the cross-app export-JWT verify)
- **xadesjs** + `@xmldom/xmldom` + `xpath` – XAdES signature verification for the eIDAS LOTL trust-store pipeline
- **@nestjs/schedule** – cron pollers (domain / did:web verification, daily LOTL refresh)
- **@nestjs/terminus** – DB health check

## Prerequisites

- Node 20 (see `@types/node` 20)
- **pnpm** (repo is a pnpm workspace – see `pnpm-workspace.yaml`)
- PostgreSQL (local or via `docker compose`)
- `openssl` on `PATH` (the `certificates` module shells out to it to mint per-user certs)
- A Clerk application (secret key + webhook signing secret)

## Environment variables

> The committed `.env.example` is **stale** in several places. The table below is the corrected, code-verified set. Correction sources are cited `path:line`.

### Corrections vs current `.env.example` / README

- **`APP_PORT` defaults to `3100`, plain HTTP.** `main.ts:32` does `app.listen(process.env.APP_PORT || 3100)` over the default (HTTP) server. The current README says "HTTPS only (port 3200)" and `.env.example` sets `APP_PORT=3200` – both stale. There is no HTTPS server and no `3200` in `main.ts`.
- **`HALCOM_CERT_PRIVATE_KEY` is required but missing from `.env.example`.** It is the RS256 platform signer used by `signJWTWithX5c`. `.env.example` instead ships `HALCOM_CERT_P12_PASSWORD`, which is **read nowhere** in the code.
- **`EIDAS_LOTL_URL` / `EIDAS_LOTL_SIGNERS_DIR` are read but absent from `.env.example`.** Both have in-code defaults; set them to pin the eIDAS trust source.
- **`CREDENTIAL_X5C_HEADER` (in `.env.example`) is read nowhere** – stale, drop it.
- **`CLERK_PUBLISHABLE_KEY` (in `.env.example`) is read nowhere** – the backend only needs `CLERK_SECRET_KEY`. (The publishable key belongs to the UI.)

### Required

| Var | Used for |
|---|---|
| `DATABASE_HOSTNAME` | Postgres connection (app + `typeorm.config.ts`) |
| `DATABASE_PORT` | Postgres connection |
| `DATABASE_USER` | Postgres connection |
| `DATABASE_PASSWORD` | Postgres connection |
| `DATABASE_NAME` | Postgres connection |
| `CLERK_SECRET_KEY` | Clerk SDK auth + Clerk API call in `/v1/credentials/export` |
| `CLERK_WEBHOOK_SIGNING_SECRET` | `svix` verification of the Clerk webhook (over the raw body) |
| `SIGNATURE_KEY_D` / `SIGNATURE_KEY_X` / `SIGNATURE_KEY_Y` | EC P-256 keypair for the `jose` ES256 VC path (did:web VCs) |
| `HALCOM_CERT_PRIVATE_KEY` | RS256 platform signer for `signJWTWithX5c` (**missing from `.env.example` – add it**) |
| `LICCIUM_CLERK_KEYS_KID` / `LICCIUM_CLERK_KEYS_N` / `LICCIUM_CLERK_KEYS_E` | Rebuild the RSA public key that verifies the cross-app export JWT (`/v1/credentials/export`) |
| `CERT_SECRET_KEY` | ACME HTTP-01 response at `/.well-known/acme-challenge/:id` |
| `TERMS_AND_CONDITIONS_URL` | Read in the signature-challenge message (`users.service.ts:455`) |

### Optional (have in-code defaults)

| Var | Default behaviour | Used for |
|---|---|---|
| `APP_PORT` | `3100` (plain HTTP) | Listen port (`main.ts:32`) |
| `EIDAS_LOTL_URL` | code default | eIDAS List-of-Trusted-Lists source (**not in `.env.example`**) |
| `EIDAS_LOTL_SIGNERS_DIR` | code default | LOTL signer certs dir (**not in `.env.example`**) |
| `NODE_ENV` | – | Log level / prod-vs-dev behaviour |

### Stale keys to remove from `.env.example`

| Key | Why |
|---|---|
| `HALCOM_CERT_P12_PASSWORD` | Read nowhere; replace with `HALCOM_CERT_PRIVATE_KEY` |
| `CREDENTIAL_X5C_HEADER` | Read nowhere |
| `CLERK_PUBLISHABLE_KEY` | Read nowhere (backend needs only the secret key) |

## Install & run

```bash
pnpm install
```

Run directly (watch mode):

```bash
pnpm run dev          # NODE_ENV=development, nest start --watch
pnpm run start        # NODE_ENV=production, node dist/src/main
pnpm run start:prod   # node dist/main
```

Run in Docker:

```bash
docker compose up                                 # dev (docker-compose.yml)
docker compose -f docker-compose-prod.yml up      # prod
pnpm run dev:dock                                 # rebuild + detached compose
```

Tests:

```bash
pnpm run test        # unit
pnpm run test:e2e    # e2e
pnpm run test:cov    # coverage
```

## Database migrations

Migrations live in `src/migrations/`. On boot the app runs `migrationsRun: true` (`app.module.ts:39`), so a normal start applies pending migrations. The standalone CLI DataSource is `typeorm.config.ts` (globs entities/migrations from `dist/`, so build first).

```bash
pnpm run typeorm:run-migrations                              # migration:run
pnpm run typeorm:generate-migration --name=<Name>           # generate from entity diff
pnpm run typeorm:create-migration --name=<Name>             # empty migration
pnpm run typeorm:revert-migration                           # revert last
# convenience shell wrappers:
pnpm run mig:gen   # scripts/generate_migration.sh
pnpm run mig:up    # scripts/migration_up.sh
pnpm run mig:down  # scripts/migration_down.sh
```

## Clerk webhook (local development via ngrok)

User rows are created by the Clerk webhook, **not** by the frontend. `POST /v1/webhooks/clerk` verifies the `svix` signature with `CLERK_WEBHOOK_SIGNING_SECRET` over the raw body, then handles `user.created` / `user.updated` / `user.deleted`. (A DB user is only created once Clerk metadata carries `termsAreAccepted` + `termsLink`; otherwise creation is deferred to a later `user.updated`.)

Because Clerk must reach your local instance over a public HTTPS URL, expose it with ngrok:

### 1. Install ngrok

```bash
brew install ngrok
# or download from https://ngrok.com/download, then:
ngrok config add-authtoken <your-authtoken>
```

### 2. Start the tunnel

> **Correction:** the backend listens on **plain HTTP** at `http://localhost:3100` by default (`main.ts:32`), not HTTPS/3200 as the current README states. Point ngrok at the actual port; drop the `--host-header=rewrite` / self-signed-cert workarounds unless you have separately fronted the app with TLS.

```bash
ngrok http http://localhost:3100
```

ngrok prints a public URL like `https://a1b2-12-34-56-78.ngrok-free.app`.

### 3. Register the endpoint in Clerk Dashboard

1. **Clerk Dashboard → Webhooks → Add Endpoint**
2. URL: `https://<your-ngrok-subdomain>.ngrok-free.app/v1/webhooks/clerk`
3. Subscribe to: `user.created`, `user.updated`, `user.deleted`
4. **Create** – Clerk shows the **Signing Secret** (`whsec_...`)

### 4. Set the secret and restart

```
CLERK_WEBHOOK_SIGNING_SECRET=whsec_...
```

Restart the backend; Clerk now POSTs user lifecycle events to the local instance.

## Architecture

Auth model (two-layer Clerk gate), module inventory, the VC issuance/accept/verify state machine, the eIDAS LOTL trust-store pipeline, and the full data model are documented in the `specifications` repo:

- Architecture overview – services, ports, data flow
- Verifiable Credential catalog – every VC type the backend issues
- Connections & issuance – the request → accept → cert-signed verify state machine
- Signing & trust model – the three signing paths + eIDAS LOTL trust store
- API reference and Data model

Key facts: every route is under `/v1` except version-neutral `health` and `/`; a global middleware gate rejects any request without a Clerk `userId` (except `.well-known/*`, `health`, `v1/mocks(/*)`, `v1/credentials/export`, `v1/webhooks/*`); per-route `AuthGuard` then loads the DB `User`. Roles (`issuer` / `creator`) are resolved from Clerk metadata by the webhook and enforced per-handler (there is no role guard).