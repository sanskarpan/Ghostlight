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

**Use `localhost`, never `127.0.0.1`.** The instance's `EXTERNALDOMAIN` is
`localhost`, so opening `http://127.0.0.1:8080/ui/login` fails with
`Instance not found. Make sure you got the domain right` — the stack is healthy
and the URL is the problem. The two hosts are not interchangeable to Zitadel
even though they reach the same listener. `curl` and browser both need the same
catch: prefer `localhost` there too.

Verify it is up:

```powershell
curl.exe -s http://localhost:8080/.well-known/openid-configuration
# -> JSON discovery document with issuer http://localhost:8080
```

## First use: machine user + PAT for API development

Go code must never log in as the human admin. A machine user
`ghostlight-dev` already exists in the local instance (created 1 Nov 2026
via the console), with a PAT stored **outside the repo** at
`%TEMP%/opencode/rendercheck/zitadel_pat.txt` (alongside the other local-only
credential files; never commit it, never put it in the repo):

```powershell
$env:ZITADEL_DOMAIN = "localhost:8080"
$env:ZITADEL_PAT = (Get-Content $env:TEMP\opencode\rendercheck\zitadel_pat.txt).Trim()
# Go: Authorization: Bearer $env:ZITADEL_PAT against http://$env:ZITADEL_DOMAIN
```

Verified working: `ListUsers` and `GetMyUser` return 200 as
`ghostlight-dev`. To create another machine user or rotate the PAT, repeat
the console flow below (log in as `admin@ghostlight.localhost` + the dev
password; the first login forces a password change, which is then the
password in `.env.dev`):

1. **Users → Service Accounts → New** (machine users live under the
   Service Accounts tab, not Users), name e.g. `ghostlight-dev`.
2. Open the user → **Personal Access Tokens → New** (expiration is
   optional), copy the token **once** (it is never shown again).
3. No roles are granted yet — add only what the endpoint under
   development needs (Role Assignments on the user).

If the PAT is lost, create a new one the same way; if the instance is
wiped (`down -v`), the machine user is gone too and must be recreated —
machines are cheap here.

Management API base: `http://localhost:8080/admin/v1/...`,
Auth API: `http://localhost:8080/auth/v1/...`, OIDC issuer:
`http://localhost:8080`. Regenerate the PAT with `down -v` wipes
everything — that is expected; machines are cheap here.

Login details (v4): the login UI is a separate `zitadel-login` container
served under `/ui/v2/login` on the same origin via Traefik — a core-only
deploy 404s every interactive login. Sign in as
`admin@ghostlight.localhost` (the org domain is part of the login name),
not bare `admin`. The PAT the setup writes to the shared bootstrap volume
is the login container's API credential, not a user token.

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

## Registering the console as an OIDC client

**Verified live 6 November 2026.** A real application was created in this
instance and a browser signed in through it into the console. The five clicks
below are what was actually done, and the notes record what the live run
taught that the docs did not.

The console's sign-in (`FE-2`, `internal/webui/oidc.go`) needs an application
registered in this instance. It is a one-time step in the console, done as the
human admin — a machine user cannot create it without project membership, and
granting that membership to a dev PAT would widen a credential that exists only
to read.

1. Sign in at `http://localhost:8080` as `admin@ghostlight.localhost`.
2. Project (or create one, e.g. `ghostlight`) → **New application** → type
   **Web**, name `ghostlight-console`.
3. Authentication method: **PKCE** (the flow always sends S256; a client
   configured without PKCE will refuse the exchange).
4. Redirect URI: **`http://localhost:8080/auth/callback`** — exact match, no
   trailing slash. The flow's redirect URI must equal this byte for byte.
5. After creating it, Zitadel shows the **Client ID**. That and the issuer are
   the two required values.

Then start the server with:

```powershell
$env:GHOSTLIGHT_WEBUI_KEY = "64 hex characters (32 bytes)"
$env:ZITADEL_ISSUER      = "http://localhost:8080"
$env:ZITADEL_CLIENT_ID   = "<the client id from step 5>"
$env:ZITADEL_REDIRECT_URI = "http://localhost:8080/auth/callback"
go run ./cmd/server
```

`ZITADEL_CLIENT_SECRET` is optional: a PKCE web app does not need one, and
leaving it unset is the correct configuration for this client type.

### What the live run established (6 November 2026)

- **The console and the identity provider must share a site.** Chrome treats
  `localhost` and `127.0.0.1` as different sites. A console served on
  `127.0.0.1:8199` with Zitadel on `localhost:8080` produced a redirect loop:
  the callback set a `SameSite=Lax` cookie that the browser did not send on the
  next navigation, so every page saw an unauthenticated browser. Register
  `http://localhost:8199/auth/callback` (not `127.0.0.1`) and run the console on
  `localhost` when the provider is there.
- **The redirect URI must be committed with the `+` button, then saved.** Typing
  into the field and pressing Save does not add it; the field is an input, not
  the list. The live run failed with `The requested redirect_uri is missing in
  the client configuration` until the `+` was used.
- **The session's subject is Zitadel's numeric user ID, not the login name.** A
  token for `admin@ghostlight.localhost` carries `sub=397722362466336772`. Any
  principal map keyed by login name will find no principal and every page will
  redirect to sign-in with the session valid in the database — a confusing
  failure, because sign-in genuinely succeeded.

With those unset, `/login` serves an explanation page with `503` rather than a
broken form — the console still runs, it just cannot sign anyone in. That is
deliberate: a missing provider and a broken provider are different states.

## MFA enrolment and recovery (verified live 7 November 2026)

The provider-side second factor was exercised end to end against this
instance, and the console session now records what the provider asserted.

**Round-trips proven, in order:**

1. **Enrolment.** The TOTP factor was added through the provider's own UI
   (account → Password and Security → Multifactor → Add Factor → Authenticator
   Application for TOTP). The dialog shows the base32 secret in text; a code
   computed locally with RFC 6238 (SHA-1, 6 digits, 30 s) verified it.
2. **Enforcement.** The moment the factor was active, the still-open console
   session was refused with `permission_denied: mfa required (AUTHZ-Kl3p0)`
   and forced back through login — the provider polices the factor it was
   given.
3. **Demand + acceptance.** A fresh login demanded "Verify 2-Factor" after the
   password and accepted the locally computed code. This ran twice.
4. **The wire to our session.** The ID token minted after a password+TOTP
   sign-in carries `amr: ["pwd","otp","mfa"]` (observed by exchanging a real
   authorization code). The callback maps that through
   `webui.SecondFactorVerified` into the session's `MFAVerified` record;
   `cmd/server`'s stub-provider test pins the full handler chain.
5. **Recovery.** Removing the factor (provider UI → Remove Second factor →
   Delete) and ending the provider session returned sign-in to password-only.
   A fresh login after recovery minted `amr: ["pwd"]` — no second factor —
   so the session honestly records `MFAVerified=false` again.

**What the live run taught that the docs did not:**

- **A warm session continuation keeps the amr of how it was established.**
  After the factor was deleted, a login continued from the still-valid
  provider session *still* minted `["pwd","otp","mfa"]` — the assertion
  describes the session's establishment, not the account's current factors.
  Only after ending the provider session did a fresh login report `["pwd"]`.
  Code that wants the post-recovery shape must force a fresh login.
- **The amr vocabulary observed:** `pwd` (password), `otp` (TOTP), `mfa`
  (multi-factor marker). `webui.SecondFactorVerified` accepts the second
  factor family (`mfa`, `otp`, `otp_sms`, `otp_email`, `sms`, `hwk`, `fido2`,
  `u2f`, `swk`) and fails closed on everything else, including an absent
  claim.
- **`/v2/sessions` is not served by this build** (404), so the session API
  cannot drive sign-ins here; the classic authorize flow plus a probe client
  is the way to observe tokens. The `amr-probe` application
  (client ID `398452085093302275`, PKCE, redirect
  `http://localhost:8199/dev-callback`, development mode) exists for exactly
  that: authorize for it lands on a console 404, which keeps the code in the
  address bar for an out-of-band exchange.
- **The admin user's TOTP factor is deliberately absent** after the recovery
  proof. Re-enrol it the same way before any work that needs the second
  factor; the enrolment takes about a minute.
