# User suggestions verification — 18 October 2026

Extension version **0.8.31**; PostgreSQL migration **0011**.

| Check | Result |
| --- | --- |
| Suggestions, scan-feedback and account-role backend regression | 50 passed |
| PostgreSQL suggestions, scan-feedback and relational integration | 41 passed, 1 skipped |
| Extension JavaScript suite | 246 passed |
| Actual MV3 Chrome workflow, feedback and suggestions | 12 checks passed |
| Live local API suggestion endpoints and authentication | Verified |
| Live PostgreSQL schema, runtime table permissions and migration ledger | Verified |

These runs overlap; the figures are not a unique combined test total. The skipped
PostgreSQL test requires a separate disposable runtime-role connection URL that
was not supplied to this test launcher. The live runtime role's table privileges
and structural health were verified separately.

The PostgreSQL run exposed a timezone-format difference when the server returned
timestamps in its configured UTC+3 zone. Suggestion timestamps are now explicitly
normalized to UTC; the repeated PostgreSQL run passed.

The browser test used generated accounts, synthetic evidence and an isolated
Chrome profile. It verified user submission without a scan reference, escaped
HTML, administrator-only controls, saved progress and response, a narrow viewport
and the author's return visit. Existing scan-feedback tests also confirmed that
Critical containment stays active after a review.

A private backup preceded the additive live migration. Existing row counts were
unchanged, including 16 scans, 16 security events, 1 incident case and 187 audit
records at deployment. The suggestions table starts empty until a real user
submits an idea; test submissions were kept out of the live database.

The local API was restarted using its existing background supervisor and exposes
both suggestion endpoints. Unauthenticated access returns 401. The installed
unpacked extension and distribution ZIP were updated. The temporary public
gateway received a new URL during restart; its current origin is embedded in the
updated distribution ZIP. Other devices using an older temporary origin need the
updated package. Local installation continues to use the loopback API.
