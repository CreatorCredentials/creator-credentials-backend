CREATOR_CREDENTIAL_BACKEND

## Installation

```bash
$ pnpm install
```

## Running the app in a docker image:
```
docker compose up # dev
# or
docker compose up -f docker-compose-prod.yml (prod)
```
## Running the app

```bash
# production run of local build
$ pnpm run start

# watch mode
$ pnpm run dev

# watch mode at docker compose
$ pnpm run dev:dock

# production mode
$ pnpm run start:prod
```

## Test

```bash
# unit tests
$ pnpm run test

# e2e tests
$ pnpm run test:e2e

# test coverage
$ pnpm run test:cov
```

---

## Clerk Webhook Setup (local development via ngrok)

The server runs on **HTTPS only** (port 3200) because Clerk requires HTTPS for webhook delivery.
Ngrok is used to expose the local instance to the internet so Clerk can reach it.

### 1. Install ngrok

```bash
brew install ngrok
```

Or download from https://ngrok.com/download. Create a free account and authenticate:

```bash
ngrok config add-authtoken <your-authtoken>
```

### 2. Start the ngrok tunnel

The backend listens on `https://localhost:3200` with a self-signed certificate.
Ngrok must connect to the HTTPS endpoint directly:

```bash
ngrok http https://localhost:3200 --host-header=rewrite
```

The `--host-header=rewrite` flag rewrites the `Host` header to match the target,
which is required when the upstream uses a self-signed cert tied to `localhost`.

If ngrok complains about certificate verification, create `~/.config/ngrok/ngrok.yml`
and point it at the local cert (found at `./secrets/localhost.crt` inside the project):

```yaml
version: "3"
authtoken: <your-authtoken>
tunnels:
  backend:
    proto: http
    addr: https://localhost:3200
    host_header: rewrite
```

Then start with:

```bash
ngrok start backend
```

Ngrok will print a public HTTPS URL such as `https://a1b2-12-34-56-78.ngrok-free.app`.

### 3. Register the webhook endpoint in Clerk Dashboard

1. Go to **Clerk Dashboard → Webhooks → Add Endpoint**
2. Set the URL to:
   ```
   https://<your-ngrok-subdomain>.ngrok-free.app/v1/webhooks/clerk
   ```
3. Subscribe to these events:
   - `user.created`
   - `user.updated`
   - `user.deleted`
4. Click **Create**. Clerk will show the **Signing Secret** (`whsec_...`).

### 4. Set the signing secret in .env

```
CLERK_WEBHOOK_SIGNING_SECRET=whsec_...
```

Restart the backend. Clerk will now POST to the local instance whenever a user
signs up, updates their profile, or is deleted — no more manual record creation
from the UI on every page load.
