# ExtSecure core scope

Removed at the project owner's request: advanced database monitoring; policy draft/review/activation workflows; incident assignment rules, reviewer inbox and scheduled escalation; general domain importing; control-effectiveness dashboards, control assessments and navigation telemetry; migration checksum comparison.

Retained: relational database integrity and queries, basic ordered transactional migrations, backup and recovery tests, query optimization, allowlisted evidence export, risk scoring and severity display, device inventory, accounts and 2FA, exceptions and website approvals, scanning, weekly/monthly reports, high-severity alerts, privacy, detection quality evaluation, usability checks and guidance.

Incident cases retain investigators, notes, timeline, status and resolution. High/Critical detections create a containment investigation and a persistent block. This core safety behavior does not depend on configurable automation. Resolving a case does not release its threat block; an administrator must explicitly confirm release.

Migration 0004 deletes six optional-feature tables, retaining scans, incidents, notes, threat blocks, active scoring configuration and historical administrative audit evidence. Historical migrations stay in sequence for upgrade compatibility. Their old SQL definitions are historical schema instructions, not enabled features. Migration execution tracks versions only; the obsolete checksum column is removed.
