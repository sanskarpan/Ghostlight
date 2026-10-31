# Local Zitadel (development only)

Throwaway Zitadel v4 identity server + PostgreSQL for developing the
Ghostlight identity integration (ADR G-038: self-hosted Zitadel). Console
and API on **http://localhost:8080**.

> **NOT production, NOT a sandbox, NOT customer-facing.** No credential lives
> in `docker-compose.yml` on purpose — secrets live in `zitadel/.env.dev`
> (gitignored; copy `.env.dev.example` once). Production uses real secrets
> from a vault, TLS, and the commercial licence if AGPL obligations trigger.

## Quick start

Prerequisite: Docker with Compose v2. All commands run from the repo root.

```powershell
cp zitadel/.env.dev.example zitadel/.env.dev
# fill in the CHANGEME values (dev-only; they apply on first init only)
docker compose -f zitadel/docker-compose.yml up -d
# first boot: init (role+database) -> setup (migrations, org+admin) -> serve
# console: http://localhost:8080  (user `admin`, password from .env.dev)
docker compose -f zitadel/docker-compose.yml down      # stop, keep data
docker compose -f zitadel/docker-compose.yml down -v   # stop AND wipe all data
```

Verify it is up:

```powershell
curl.exe -s http://localhost:8080/.well-known/openid-configuration
# -> JSON discovery document with issuer http://localhost:8080
```

## First use: machine user + PAT for API development

Go code must never log in as the human admin. Create a machine user once,
in the console:

1. Log in at http://localhost:8080 with `admin` / the dev password.
2. Select the **Ghostlight** organization (top-left context switcher).
3. **Users → New → Machine user**, name e.g. `ghostlight-dev`, access token
   type **JWT** (or Bearer), no roles yet — grant only what the endpoint
   under development needs.
4. Open the machine user → **Personal Access Tokens → New**, copy the token
   **once** (it is never shown again).

Use it from a shell (never commit it, never put it in the repo):

```powershell
$env:ZITADEL_DOMAIN = "localhost:8080"
$env:ZITADEL_PAT = "<paste-once>"
# Go: Authorization: Bearer $env:ZITADEL_PAT against http://$env:ZITADEL_DOMAIN
```

Management API base: `http://localhost:8080/admin/v1/...`,
Auth API: `http://localhost:8080/auth/v1/...`, OIDC issuer:
`http://localhost:8080`. Regenerate the PAT with `down -v` wipes
everything — that is expected; machines are cheap here.

## What we learned setting this up

Zitadel's setup assumes **either** the documented happy path (the postgres
superuser provisions role+database via `start-from-init`) **or** an
externally pre-provisioned role/database **plus** an explicit
`zitadel init zitadel` schema-bootstrap before `setup`. Pre-provisioning the
role in a postgres init script but skipping `init zitadel` lands in the gap
and fails at migration `40_init_push_func_v4` querying `eventstore.events`
before it exists (upstream zitadel/zitadel#9363). This compose therefore runs
one `start-from-init` service and mounts **no** init scripts.

## Production notes (for later, not here)

- Secrets (masterkey, DB passwords, PATs) come from a vault, never compose.
- TLS on, external domain, `ZITADEL_EXTERNALSECURE=true`.
- Decide AGPL vs commercial licence before modifying/serving the core.
- The sandbox qualification (real SSO/SCIM round-trips, GQ.4/G7.10) still
  needs the hosted/proper environment — this container proves the
  integration shapes, not the qualification.

## Layout

- `docker-compose.yml` — db + zitadel (`start-from-init`), pinned image
  `ghcr.io/zitadel/zitadel:v4.20.0`, data in named volume `zitadel-db-data`.
