# Incident safety and removal

Version 0.8.14 adds a case-specific safety checklist, audited operator confirmations, affected-device protection, and administrator incident removal. No removed workflow automation has been restored.

Safety actions are matched to website or file incidents. They cover evidence review, notifying the affected user through an approved channel, stopping interaction, file execution precautions or credential/session review, and reviewing a fresh scan before release. A checked item records an operator statement, not proof of remediation.

Administrators and the head administrator can block a registered affected device from its case, with explicit confirmation, a reason, and both case/device revision checks. Managers can record safety reviews but cannot block devices or remove incidents. Device blocking restricts ExtSecure requests; it does not isolate the OS or quarantine files. Inventory recovery remains available to authorized administrators.

Administrators can remove incidents in any status. Removal deletes the case and its notes, preserves scans and active blocks, and records an append-only audit entry. A new note invalidates a stale removal request. Removing a containment case never releases its block; a new investigation must be created and resolved before a reviewed release. Evidence referenced by threat blocks remains outside scan retention candidates.

Verification: 213 extension unit tests, 102 affected backend tests, 24 tests against an isolated real PostgreSQL database, and 14 real Chrome checks passed. Chrome checks use synthetic threat evidence in an isolated profile and exercise the shipped UI, service worker and actual dynamic blocking rules; they do not visit live malicious sites.
