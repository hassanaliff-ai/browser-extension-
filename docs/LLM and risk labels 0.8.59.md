# ExtSecure 0.8.59 — local summaries and risk labels

The detector preserves the original VirusTotal detection counts, engine total,
report identifier and report time. Its severity badge uses the backend's existing
configured risk policy. The interface does not recalculate the score or alter the
stored scan. Low risk does not guarantee safety; unavailable evidence remains
Unknown. The LLM never sets the risk score or verdict.

Local inference now distinguishes an offline service, timeout, missing model and
busy model from invalid output. These errors reveal no prompts, private content
or raw connection diagnostics. Invalid local structured output receives one
bounded retry; service errors do not trigger inference retries. Both attempts use
the same evidence and constraints. Malformed output, invented evidence codes,
missing required citations, prohibited tools and private URLs remain rejected.
No fabricated summary or cloud fallback is saved.

The API host requires its configured Ollama runtime and installed model. Existing
startup supervision recovers a stopped runtime, but cannot recover deleted model
files without restoring them. Runtime binaries and model files remain outside
Git and the installable Chrome ZIP. Client devices use the shared API; they do not
need to install a model themselves.


Verification on 14 November 2026: 108 focused backend tests, 323 extension tests,
and five real headless Chrome checks passed. The Chrome checks use public-report
fixtures without visiting the target. Live local inference with the restored
configured model produced a validated summary in 57.9 seconds and preserved the
input score, severity and provider counts. No provider key or cloud model is used
for local inference.

The extension waits up to six minutes for its one authenticated generation job,
allowing the bounded local retry to finish without resubmitting the request.
Sign-in and role checks remain active throughout polling.

Two additional live local-model integration checks passed against an isolated test
database: saving a scan explanation (including reuse of the saved result without
changing scan score or severity), and saving a weekly period report. These checks
used synthetic scan fixtures and real local inference, without adding test scans
or reports to the shared production database.
