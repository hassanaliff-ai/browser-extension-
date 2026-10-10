-- migrate:up
DROP TABLE IF EXISTS incident_workflow_notices;
DROP TABLE IF EXISTS incident_workflow_links;
DROP TABLE IF EXISTS incident_workflow_rules;
DROP TABLE IF EXISTS security_control_reviews;
DROP TABLE IF EXISTS security_navigation_evidence;
DROP TABLE IF EXISTS security_policy_revisions;
-- migrate:down
-- irreversible: removed optional feature data cannot be reconstructed by rollback.
SELECT 1;
