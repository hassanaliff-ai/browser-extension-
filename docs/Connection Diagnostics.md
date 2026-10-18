# Extension connection diagnostics — 18 October 2026

Extension 0.8.32 displays its actual configured API address and distinguishes
network errors, timeouts, non-success HTTP status, invalid JSON and an unexpected
service. The health check allows 12 seconds for a public HTTPS connection and
continues to send no account/device credentials. A caller cannot override the
configured endpoint through the health-check message.

The source extension uses loopback for the host computer. The distribution ZIP
uses the current public HTTPS origin and includes its matching Chrome connection
policy. On another computer, loading the source `extension` folder would instead
connect to that computer's localhost. Old ZIPs can retain an expired temporary
address. Download the current ZIP, replace the files in the installed folder,
and reload the extension through `chrome://extensions`.

Verification: 248 JavaScript tests passed. A real fresh Chromium MV3 profile
loaded the public ZIP and verified five checks: extension load, successful public
health request with the packaged CSP, matching configured address, correct
connection-button result and no page JavaScript errors. No account credentials
or personal browser profile were used. The check returned `ready` against
`https://differently-prospect-hopes-conversion.trycloudflare.com` at verification.

This confirms the packaged client worked from the test host. It does not prove
which package is installed on another device or whether that network allows the
temporary tunnel domain. If it still fails, the connection message now includes
the address and failure category needed to distinguish those cases.
