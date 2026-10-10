# Incident response and threat containment

## Essential scope
- Keep normal schema upgrades, backup/restore checks, approved evidence exports and focused control testing.
- No general-purpose data importer or new advanced monitoring/escalation service is required by this change.
- Optional assignment, review and escalation workflows have been removed. Containment creates its own basic investigation without configurable automation.

## Containment
A confirmed High or Critical scan creates/updates a threat block and creates an investigation in the same transaction. URL containment covers the exact hostname across HTTP/HTTPS, ports and paths; child domains are separate. File/hash containment records the malicious fingerprint. Unknown and Medium are not automatically classified as high risk.

Website checks, consumption and new approval decisions consult the active block before any temporary or permanent grant. Notification exceptions do not bypass containment. A later lower scan does not automatically release previous high-risk evidence.

The MV3 worker stores detected host blocks locally, installs persistent declarative rules above visit approvals, revokes temporary visit rules and redirects matching open tabs. Non-navigation resources from that hostname are blocked as well. The approval gate checks backend containment before installing any allow rule. Existing approval records remain as decision history.

File bytes stay on the device. File hash blocklisting is not operating-system quarantine: Chrome extensions cannot prevent execution of an already-downloaded local file. This release does not claim automatic scanning of every file or website; containment starts when scan evidence establishes High/Critical risk.

## Incident response
Investigate -> assign an approved operator -> add evidence notes -> record investigation -> record resolution. The workspace shows the affected device, source scan, containment state, notes, timeline and recorded resolution. Resolving a case does not release its threat block.

Only an administrator or the head administrator can explicitly release a block, after the latest linked investigation is resolved, with confirmation, a reason and the current revision. Concurrent/repeated high-risk evidence invalidates an old release request and reactivates a previously released block. After release, the usual website approval gate still applies. A browser removes its stale local hostname rule when an authenticated backend check confirms no active block.

## Database evolution and privacy
The additive security_threat_blocks table uses a unique primary identity, source-scan foreign key, severity constraint, timestamps and revision. Standard schema initialization creates the table without deleting existing data. Backend host identities are hashes; raw URL paths, query strings, fragments and credentials are not retained by this table. Browser rules retain only the hostname needed for enforcement. Evidence export uses an explicit field allowlist and omits credentials, raw URLs, free-form detail and local enforcement hosts.

## Deployment
Restart TestAPI after updating Python files and reload the unpacked ExtSecure extension after updating its package. The server creates the additive table on startup. Historical scans are not automatically backfilled; new assessments establish containment.
