# ExtSecure AI runtime

The Chrome extension uses a server-side model to explain stored risk evidence and prepare weekly/monthly alert reports. This integration uses an existing language model; it does not train a new foundation model. Deterministic scoring remains authoritative, and all generated prose is a review draft.

## Configuration and execution

1. Install `requirements.txt` and run the protected FastAPI service as described in `README.md`.
2. Set `OPENAI_API_KEY` and `OPENAI_MODEL` in the backend `.env`. Use a model supporting Responses structured outputs. No key belongs in the extension or Git repository. Missing settings return HTTP 503; generation errors return HTTP 502 and do not save an invented summary.
3. Load `extension/` as an unpacked Manifest V3 Chrome extension, or reload the existing installation. Version: 0.6.0.
4. After a page or file reputation scan, choose **Explain evidence and recommendations**. Optional page/text-file sharing is off by default and requires consent. Page URLs must match the exact cleaned scan URL. A selected UTF-8 file must match the scanned SHA-256. Binary files are explained using their hash findings; PDF/Office/binary parsing is not implemented.
5. The existing **Monthly reports** panel contains **Weekly and monthly AI reports**. Choose a completed UTC month or a Monday date for a completed seven-day week. Head/Administrators generate; Managers review; Normal users can only explain their own scans. Download the complete JSON archive to obtain all period alerts and stored AI explanations, not only recent table entries.

The model receives fixed evidence categories and aggregate report counts. Common addresses, URLs and credential assignments are removed from optional excerpts before model submission. This redaction is not a guarantee that all personal information has been removed: only share content authorized for processing by the configured provider. Raw content is not stored. Model requests use `store=False`, no tools, bounded output and timeouts. Provider processing still occurs outside the device.

Public text fetching accepts HTTPS port 443 only, blocks all private/reserved resolved addresses, pins a validated IP with certificate/hostname verification, strips queries/fragments, refuses redirects and compression, bounds input to 256 KiB and text to 12,000 characters, and executes nothing. Page text is context, not a confirmed malware signal. The model may still make mistakes; review its narrative against original findings.

Explanations use the scan's existing ownership controls and cascade on scan deletion. Historical report snapshots retain their own archive for administrator review. Stats cover half-open `[start,end)` UTC ranges. Alert status is measured at generation, not reconstructed at the original period end. Explanation counts count generated explanation records; `explained_scans` counts distinct scanned items. Later-arriving records do not alter an existing snapshot. Download all rows from the snapshot; the browser's history list contains only the most recent reports.

## Repeatable reporting job

From the installation folder, run:

```powershell
python -m alba_security.intelligence_runner --kind both --language ar
```

Run this command daily through the deployment's scheduler to prepare the previous closed UTC week and month. The unique `(kind,period,language)` constraint makes repeated runs return the existing draft. Scheduling has not been installed on the user's Windows account. The new periodic job saves drafts and never sends them automatically. Existing reviewed monthly email delivery remains available in the original monthly report workflow once SMTP/admin recipients are configured.

## API and verification

- `GET /monitor/api/intelligence/scans/{scan_id}`: saved explanations after ownership checking.
- `POST /monitor/api/intelligence/scans/{scan_id}/explain`: language plus optional consented page or base64 UTF-8 file.
- `GET /monitor/api/intelligence/reports`: recent saved weekly/monthly report snapshots.
- `POST /monitor/api/intelligence/reports/generate`: `kind`, `period`, `language`.

Generation is limited to three requests per approved account per minute within one API process. Use a shared deployment limiter for multiple workers. Read-only retrieval requires the same authenticated permissions. All API responses prohibit caching. No production credentials or scan databases are included in the source package.

```powershell
python -m pytest
node --test extension/tests/*.test.js
```

Tests cover SSRF/private resolution, content boundaries, unsupported binary input, consent, context identity, personal ownership, structured output validation, unknown/invented model evidence, closed weekly/monthly ranges, exact period archives, idempotence and private caching. Automated model responses and Chrome APIs are substituted in tests. Real provider/content tests are reported separately; they do not prove live LLM generation without configured credentials.

Implementation reference: [OpenAI Structured Outputs](https://developers.openai.com/api/docs/guides/structured-outputs?api-mode=responses).
