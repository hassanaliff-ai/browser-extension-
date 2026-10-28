# Shared SecureScope HTTPS API

The shared extension package uses `https://ken05ghoul.tail75c8f9.ts.net`.
On 28 October 2026, its `/health` returned `status: ok` and
`api_provider: SecureScope`; `/extension/capabilities` advertised
`/api/v1/check` for website scans and `/api/v1/rdap` for domain-age checks.

The address belongs to Hasan's Tailscale device. Funnel currently forwards
HTTPS requests to his existing FastAPI service at `http://127.0.0.1:8765`.
Hasan confirmed that service uses his existing `extsecure` PostgreSQL database
and `public` schema. The public health response cannot independently verify
the database connection. No accounts or databases were copied by this change.

Hasan's computer, API and Tailscale must remain running. Retain the device and
tailnet hostname to retain this address. On another computer, `127.0.0.1`
refers to that other computer; it does not reach Hasan's database.

## Update an existing extension

1. Download `ExtSecure Chrome Extension.zip` from this repository and extract it.
2. Replace release files in the same folder Chrome already loads. Preserve
   Chrome-generated `_metadata` and browser storage.
3. Open `chrome://extensions` and click Reload on ExtSecure.
4. Use Check API connection and confirm the shared HTTPS address above.
5. Sign in with the existing approved account and complete authenticator
   verification. Changing the API address does not grant account approval.

Uploading a ZIP to GitHub does not replace another computer's unpacked
extension files. Each installation needs the replacement and reload steps.

## Rebuild the shared ZIP

Repository `extension/` source defaults to localhost for development. The
packager changes the release's API origin, content security policy and
navigation allow rule together. After verifying the shared API, run in the
project's Python environment:

```powershell
python -c "from scripts.start_public_api import package; print(package('https://ken05ghoul.tail75c8f9.ts.net', fixed=True))"
```

Publish source changes, tests and the rebuilt ZIP together. Never include
`.env`, database files, account exports, credentials, personal documents or
Chrome-generated metadata in the archive.

## Optional restricted gateway

The `scripts.fixed_https_api` workflow prepares a separate loopback gateway
on the API host. It permits supported API paths, blocks `/docs`, strips
untrusted forwarding headers and applies a shared public request limit.
This workflow does not change the currently running Funnel automatically.

1. Run `python -m scripts.fixed_https_api prepare` on the API host. This starts
   the gateway on `127.0.0.1:8768` without exposing it publicly.
2. After reviewing the public access change, run
   `tailscale funnel --bg 8768` on that same host and follow any activation
   prompt. Check `tailscale funnel status` to confirm the target is port 8768.
3. Run `python -m scripts.fixed_https_api finalize`. It verifies the public
   SecureScope health response, a protected account route, and blocked public
   API documentation before rebuilding the ZIP for that host's hostname.

The gateway process also needs to remain running when this optional workflow
is used. It does not merge databases or change account roles and approvals.
