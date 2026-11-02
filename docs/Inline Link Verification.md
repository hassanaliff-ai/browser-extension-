# SecureScope inline warnings in the shared extension

Client 0.8.50 includes the standalone prototype's bounded inline scanner and
local URL indicators in the shared extension package. The manifest loads
`inline-links.js` and `inline-links.css` at document idle in top-level HTTP(S)
pages. The background worker accepts one dedicated content-script message
and retains its existing trusted-extension-page restriction for all other
actions. A non-expired account session is required for inline replies.

## Data and behavior

- Only site origins reach the worker. Requests with paths, queries, fragments,
  credentials, non-HTTP schemes or more than 50 origins are rejected.
- Local checks use no fetch, backend token transmission, persistent history,
  account modification, approval change or containment operation.
- Repeated origins reuse their result; added and changed links are handled.
  Changed destinations lose the old badge before another result is applied.
- Limits remain 2000 anchors and 500 origins per page, with batches of 50.
- Medium, High and Critical indicators produce a **local warning**. Hover text
  explains the reasons and states that no backend lookup was performed.
  A Low result or missing badge is not a certificate of safety. Loopback
  development addresses remain Unknown rather than an IP-address warning.
- Local indicators are heuristic and uncalibrated. Detection accuracy, false
  warnings and real-browser performance still require controlled evaluation.

## Automated verification

Run from the repository root:

```powershell
node --test extension/tests/inline-checks.test.js extension/tests/inline-links.test.js extension/tests/worker.test.js
node --test extension/tests/*.test.js
```

The inline DOM tests simulate page mutation and batches. Worker tests cover
the actual registered message listener, sign-in requirement, origin-only
validation, absence of network/storage side effects, and continued rejection
of content-script administrator actions. They are not Chrome performance or
phishing detection benchmarks.

## Real-browser check still required

After the existing API is reachable, back up and update the same unpacked
extension folder, preserve browser metadata, and reload with the user's
permission. Use an authorized test profile and a controlled local fixture
containing reserved `https://paypal.com.evil.example` and benign-looking
`https://www.paypal.com` links. Do not navigate to suspicious live targets.

Check that the reserved impersonation example receives a local warning,
private URL components do not enter runtime messages, and changing its href
removes the old badge. Check new links and repeated origins. Confirm an
unauthenticated profile cannot request protected API actions through the
content-script path. Record the actual build and observations separately
from automated results. Inline checks do not require a backend restart.
