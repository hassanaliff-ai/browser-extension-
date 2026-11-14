# SecureScope reputation evidence and incident rules — 0.8.58

SecureScope's primary `/api/v1/check` route uses the existing private backend
VirusTotal client. The operational `extension/` keeps one account, inventory,
scan-history and incident system. Its popup, Scan a page, downloaded-file results,
saved scan details and Incident cases now share the same provider-evidence panel.
Basel's bounded inline-link warnings and RDAP module remain in their existing
places; inline checks remain local and do not claim VirusTotal coverage.

## Provider evidence and the policy score

VirusTotal's malicious, suspicious, harmless and undetected engine counts are
shown exactly as supplied. Missing categories display Unavailable rather than an
invented zero. The report analysis time is retained when supplied; cache hits
are labelled. Undetected does not certify harmlessness.

Detector screens show one VirusTotal result with engine counts and no separate
0–100 score. The displayed result follows those counts, not ExtSecure's internal
policy score. Each explicit website/QR check through `/api/v1/check` and each
authenticated file check requests a fresh provider report; it does not silently
substitute a previous cached verdict. Quota and provider errors remain Unknown.
Saved history remains the original report snapshot rather than a fresh scan.
Legacy ingestion may still use its existing cache.

Manual checks now include the submitted page path by default. The toolbar's
current-page action and QR checks use the same default. Queries and fragments
remain stripped, and credentials are rejected. Home-page-only checking is an
explicit choice, clearly labelled in the form. The immediate result shows the
cleaned address actually sent; original page paths are not added to historical
event metadata. Saved evidence includes the provider's report ID, analysis time
and total engine count, so reports can be compared without silently substituting
a domain/home-page report for a particular URL.

The reported AMTSO mismatch was a comparison between the home-page report
`https://www.amtso.org/` and the report for
`https://www.amtso.org/check-desktop-phishing-page/`. A read-only provider lookup
of the latter returned 12 malicious, 0 suspicious, 48 harmless and 33 undetected
results (93 engines), with analysis time 11 November 2026 at 05:24:43 UTC.
Those numbers are report evidence, not hard-coded production detections. Future
provider updates may change them. Regression tests use a fixed snapshot, while
production always displays the fetched report.

The internal policy score remains available for incident prioritization and
blocking. It is not a VirusTotal percentage or probability of infection.
For the authenticated browser integration, any malicious
provider detection activates the malicious signal, and any suspicious detection
activates the suspicious signal. Under the default policy, URL findings carry
80/30 points and file findings 90/40 points respectively; combined findings cap
at 100. Installed administrator policy weights remain authoritative. RDAP is
separate evidence, not a provider detection count. Prior scans are not rescored.

When reputation is unavailable, the result stays Unknown with no numerical score,
even when registration-age evidence is known. No successful VirusTotal verdict
is fabricated from an unavailable report or local inline rules. The legacy
general-purpose client's verdict thresholds remain compatible with its existing
public contract; the browser's evidence mapping is explicitly labelled
`extsecure-provider-evidence-v1`.

## Incident categories

The existing Incident cases workspace exposes eight categories:

1. Phishing findings require an explicit malicious/suspicious engine phishing label.
2. Malicious websites require the linked URL's malicious reputation finding.
3. Malicious downloads require a malicious hash finding.
4. Malicious IP reputation follows a malicious IP scan signal.
5. Suspicious reputation follows a suspicious finding.
6. Extension security findings support manual investigation of recorded indicators.
7. Recent domain registration supports manual review, not an infection diagnosis.
8. Manual evidence review supports other scan-linked investigations.

Malicious and suspicious findings create one case per scan. Existing containment
investigations are reused; manual creation locks the source scan and reuses an
existing case. Unknown and exception-only results do not automatically create
cases. A repeated scan remains a distinct piece of evidence and may have its own
investigation. High/Critical containment remains active until separately released;
acknowledging an alert or resolving a case does not remove the block.

No fabricated incidents are inserted into the shared database. The category guide
is in the incident workspace. Demonstration results exist only in isolated test
fixtures, with synthetic accounts and reserved example domains.

## Storage and deployment

Provider evidence is saved in the existing scan-completed security event, in the
same transaction as scan findings, ownership and cases. History and cases read
that saved evidence rather than querying a current report and rewriting history.
Only counts, fixed categories, analysis time and provenance are retained; keys,
raw vendor labels, URLs and report bodies are excluded from this evidence object.

Migration `0013_provider_evidence_cache.sql` adds one nullable JSON column to the
existing file cache so cached file results preserve their original counts. Old
rows remain readable and their absent evidence is not invented. SQLite development
upgrades use the same additive change. Existing scans, accounts and sessions remain.

The supervisor supports an explicit, short-lived refresh request in its existing
limited Windows task context. A recorded PID, port, executable and worker command
must match before replacement. The request is consumed before stopping the worker,
preventing replay against a reused PID. HTTPS hostname and API port are unchanged.

After replacing files in an existing unpacked installation, reload ExtSecure at
`chrome://extensions` and reopen its console. GitHub updates do not automatically
reload extensions on another device.

## Verification scope

The full backend run passed 995 tests and 16 subtests, with 18 PostgreSQL-specific
checks skipped because no disposable PostgreSQL test configuration was supplied.
Subsequent targeted checks cover the final Unknown/RDAP guard, additive cache
migration, saved counts, category rules, duplicate case reuse and supervisor refresh.
The JavaScript suite and a real Chromium fixture test cover scan, incident and
compact-popup rendering, escaping and narrow-screen layout. Fixture screenshots
and logs stay private. Tests do not submit malicious sites, rerun Basel's private
evaluation or populate the production database with examples.

Version 0.8.55 verification: 102 targeted backend tests, 313 JavaScript tests and
10 Chromium checks passed. Repeated native checks invoke the provider each time;
the file test also confirms that a subsequent HTTP 429 stays Unknown instead of
reusing a cached successful report. Browser fixtures assert that no separate
numerical score is rendered. The public API advertises
`detector_report_mode: virustotal-direct-v1`.
