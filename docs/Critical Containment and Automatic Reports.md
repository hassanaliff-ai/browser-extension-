# Critical threats and automatic local LLM reports

Version 0.8.16 keeps every Critical result visible as an open alert, creates an active threat-block entry and a linked incident case, and commits these records together with the scan evidence and personal history. Critical alerts and notification delivery cannot be suppressed by a URL/domain exception. High-severity containment also remains enabled. Chrome installs persistent rules immediately when it receives a Critical URL result, removes conflicting visit grants, and redirects matching open tabs to the blocked screen. Downloaded files are denied by fingerprint and shown in the threat blocklist; the extension cannot quarantine files or stop programs at the operating-system level.

Incident cases appear in **Incident cases** and can be opened from the alert/blocklist. Removing a case does not release its threat block. A resolved linked investigation, explicit confirmation and an audited release remain required to release a block.

Two native Windows tasks are installed:

| Task | Schedule | Coverage |
|---|---|---|
| ExtSecure Automatic weekly LLM Report | Sunday, 09:00 Asia/Riyadh | Previous completed Sunday–Saturday UTC week |
| ExtSecure Automatic monthly LLM Report | Day 1, 09:00 Asia/Riyadh | Previous completed UTC month |

The background Python entry point starts the local Ollama/API services if necessary, aggregates stored evidence, calls the configured local model and saves the report into PostgreSQL. Reports appear automatically under **Reports → Weekly and monthly AI reports → Snapshot history**. Every alert and saved AI explanation in the window is included in the report archive; the model receives aggregate evidence without browsing targets, account identities or raw page/file contents. Generated narratives remain reviewable drafts. These tasks generate and save reports; they do not email unreviewed drafts.

The script runs using `pythonw.exe`, so no command-prompt window opens. Tasks run under the signed-in Windows account without saving its password. The computer must be running and the account signed in; missed schedules use Windows `StartWhenAvailable`. Failed tasks retry up to three times at ten-minute intervals. Repeated execution returns the same saved report rather than creating a duplicate or calling the model again. If the model fails, no fabricated report is saved. Private status logs are in `.private/automatic-reports.jsonl` and contain report IDs/statuses, not prompts or credentials.

Manual weekly reports retain their existing completed Monday–Sunday UTC windows. Automatic weekly reports use Sunday–Saturday windows, explicitly labeled in the Reports UI and stored statistics. Monthly boundaries remain UTC for both flows.

To reinstall the native schedule, run `scripts/install_automatic_reports.ps1` with `-PythonwPath` pointing to the project's background Python runtime, then enable `REPORT_AUTOMATION_ENABLED=1` in the private `.env` and restart TestAPI. `scripts/run_automatic_report.py --kind weekly --dry-run` and the corresponding `monthly` command show selected periods without writes or model calls.

Verification: 83 affected backend tests, 32 isolated PostgreSQL tests, 216 extension unit tests, and 14 real Chrome containment checks passed. Both actual Windows tasks were run manually for verification and completed with result 0; they saved weekly (2026-10-04 through 2026-10-10 UTC) and monthly (September 2026) reports with the configured local Ollama model.
