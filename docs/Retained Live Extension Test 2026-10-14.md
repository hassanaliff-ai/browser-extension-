# Retained live extension test 14 October 2026

The distributed ExtSecure 0.8.25 ZIP was loaded into a real Chromium extension profile and tested against the temporary public HTTPS API, live PostgreSQL and real VirusTotal lookups. No fetch mocks or invented reputation findings were used. The approved `hasan` head administrator signed in through the shipped password and authenticator screens.

All 19 checks in the completed run passed. The test device is **ExtSecure retained real test 14 October 2026**, ID `device-b0e59a31-d9a4-46b9-8fc6-23642c01efaa`. It is a retained test Chrome profile, not another physical computer or proof that a browser is currently online.

| Check | Result | Saved scan ID |
|---|---|---|
| example.com | Low, score 0, complete assessment | 7bc3012c-2d61-481f-9fa1-011835511dc2 |
| example.org | Low, score 0, complete assessment | 219c95d3-051e-47e2-bf3f-4142378ae8ce |
| Generated harmless text file | Unknown, no numeric score; VirusTotal has no report for this hash | ad67303c-383e-436c-9dfd-542501a62532 |

The file SHA-256 is `cb4cf153976cd6a6c1ca61cf3fa056d24102571c30a603d1b3ee69a19ab2871c`. Chrome calculated it locally and sent only the hash. No file was executed or uploaded. Low risk does not establish safety, and Unknown was kept separate from Low.

The browser checks covered real service-worker/API connectivity, password plus 2FA, the head role, healthy PostgreSQL storage, device enrollment, URL privacy, both URL scans, local file hashing, stored account/device attribution, history and security-event screens, devices, extensions, reports, device selection, unapproved-site blocking and absence of uncaught console JavaScript errors. No malicious page or executable was opened. The navigation check used harmless example.net and verifies the approval gate, not live malware containment. The optional permission prompt for enumerating other installed extensions was not exercised; the enrolled ExtSecure record was verified.

During the completed run, scans increased from 12 to 15, security events from 12 to 15, and personal scan ownership records from 12 to 15. The first attempt had already saved one example.com scan before a test assertion used the wrong history response shape. That record was preserved and the assertion corrected. Across both attempts, four scan results were retained. No devices, extension records, scans, incidents or security events were deleted, and no cleanup/logout API was called. Closing the isolated test browser naturally ends its in-memory extension session; records remain accessible from the normal signed-in console.

Private screenshots, the harmless file, structured results and the isolated browser profile are stored under `.private/retained-live-test-2026-10-14/`. Credentials, authenticator secrets and session tokens are excluded from this report and Git.
