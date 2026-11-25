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

Render Free can sleep after inactivity. Its first request can take about a minute. The current extension may show a connection timeout during that cold start. Wait for `/health` and retry. This service has no uptime guarantee.

Use Neon for persistent storage. Render Free local files disappear on restart and Render Free PostgreSQL expires after 30 days. Check both providers' current free quotas before deployment.

Ollama at localhost:11434 and the Windows scheduled report tasks stay on the laptop. This Blueprint leaves report automation disabled. Scans, sign-in, approvals, inventory, incidents and persisted history can run on the hosted API. AI explanations and scheduled reports require separately hosted inference and scheduling before those features can run with the laptop off. No alternate AI provider is selected automatically.

## Credentials and data

Uploading the production VirusTotal key, administrator secrets and database records requires the owner's explicit choice of hosting account and destination. The source deployment files contain no secrets. `/health` checks service readiness, while authenticated smoke checks verify PostgreSQL and permissions.

Sources reviewed 25 November 2026

- https://render.com/docs/free
- https://render.com/docs/blueprint-spec
- https://neon.com/docs/introduction/plans
