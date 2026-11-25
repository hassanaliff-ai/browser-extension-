# Free independent ExtSecure hosting

Render hosts the API with HTTPS and Neon stores PostgreSQL data independently of the laptop. This is a free development deployment with provider quotas and cold starts.

## Deploy

1. Sign in to Neon, create a Free project and copy its connection string privately.
2. Sign in to Render and create a Blueprint using this GitHub repository. Review the service plan as Free.
3. Enter the hosted PostgreSQL URL as DATABASE_URL. Supply VT_API_KEY, ADMIN_USERNAME, ADMIN_PASSWORD_HASH, ADMIN_TOTP_SECRET, ADMIN_ACCOUNT_ENCRYPTION_KEY and INGEST_TOKEN through private hosting configuration. Never put them in GitHub or chat.
4. Preserve the existing head administrator and account encryption settings if migrating existing accounts. If ADMIN_ACCOUNT_ENCRYPTION_KEY was blank, the current application derives it from ADMIN_TOTP_SECRET. Use that same derived key when migrating. A fresh deployment can use a new dedicated Fernet key.
5. Existing accounts and device records require an explicit database migration. A fresh Neon database starts empty. Back up and verify the migration before directing existing clients to it.
6. After Render reports a successful deploy, verify `/health` and `/extension/capabilities` on its actual HTTPS origin, plus a real password and authenticator login.
7. Build the installable extension for that verified origin with the existing `scripts.start_public_api.package(origin, fixed=True)` helper. Distribute it to Basel and reload the extension in its existing directory. The previous ts.net address points to the laptop and must be replaced for cloud clients.

## Availability and AI

Render Free can sleep after inactivity. Its first request can take about a minute. Extension 0.8.63 retries only anonymous health probes up to six times for Render cold starts. Protected actions are never automatically replayed. If the first wake still times out, wait for `/health` and retry. This service has no uptime guarantee.

Use Neon for persistent storage. Render Free local files disappear on restart and Render Free PostgreSQL expires after 30 days. Check both providers' current free quotas before deployment.

Ollama at localhost:11434 and the Windows scheduled report tasks stay on the laptop. This Blueprint leaves report automation disabled. Scans, sign-in, approvals, inventory, incidents and persisted history can run on the hosted API. AI explanations and scheduled reports require separately hosted inference and scheduling before those features can run with the laptop off. No alternate AI provider is selected automatically.

## Credentials and data

Uploading the production VirusTotal key, administrator secrets and database records requires the owner's explicit choice of hosting account and destination. The source deployment files contain no secrets. `/health` checks service readiness, while authenticated smoke checks verify PostgreSQL and permissions.

Sources reviewed 25 November 2026

- https://render.com/docs/free
- https://render.com/docs/blueprint-spec
- https://neon.com/docs/introduction/plans

## Live deployment — 25 November 2026

- Public API: https://extsecure-api-htg7.onrender.com
- Render Free in Virginia; external Neon PostgreSQL 18 in US East.
- 40 tables, 1,327 rows and 8 reporting views were restored from a consistent private backup. Table and view results plus schema digests matched the backup snapshot.
- Three registered accounts retained their encrypted authenticator secrets; the existing account encryption key was preserved. Personal passwords were not reset.
- The API uses a separate non-superuser PostgreSQL runtime role. It cannot create roles, modify audit history or change migration history. The client-to-Neon connection negotiates TLS.
- Public health/capability requests returned 200. An anonymous protected device request returned 401.
- Extension 0.8.63 and its ZIP use this public cloud origin. Replace files in the existing unpacked directory and reload Chrome. Each device must install this update; old ts.net packages still address the laptop.
- The local database is a pre-cutover copy. It is no longer the data source used by this release. Do not merge subsequent local and cloud writes without reviewing conflicts.
- Personal password-and-authenticator sign-in must be verified by each user; deployment checks do not establish that an unknown personal password works.
- Local Ollama and Windows report jobs remain laptop-dependent. This free API deployment does not host an LLM or run those local schedules.

Secrets, database backups, migration verification and account data remain private and are not in GitHub.
