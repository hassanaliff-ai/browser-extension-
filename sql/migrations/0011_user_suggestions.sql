-- migrate:up
CREATE TABLE IF NOT EXISTS user_suggestions (
	id VARCHAR(36) NOT NULL, 
	reporter VARCHAR(120) NOT NULL, 
	category VARCHAR(24) NOT NULL, 
	title VARCHAR(160) NOT NULL, 
	description TEXT NOT NULL, 
	content_digest VARCHAR(64) NOT NULL, 
	status VARCHAR(24) NOT NULL, 
	response TEXT, 
	reviewed_by VARCHAR(120), 
	reviewed_at TIMESTAMP WITH TIME ZONE, 
	revision INTEGER NOT NULL, 
	created_at TIMESTAMP WITH TIME ZONE NOT NULL, 
	PRIMARY KEY (id), 
	CONSTRAINT uq_suggestion_reporter_content UNIQUE (reporter, content_digest), 
	CONSTRAINT ck_suggestion_category CHECK (category IN ('feature','interface','accessibility','other')), 
	CONSTRAINT ck_suggestion_status CHECK (status IN ('new','under_review','planned','completed','declined')), 
	CONSTRAINT ck_suggestion_title CHECK (length(title) BETWEEN 5 AND 160), 
	CONSTRAINT ck_suggestion_description CHECK (length(description) BETWEEN 20 AND 3000), 
	CONSTRAINT ck_suggestion_revision CHECK (revision >= 1), 
	CONSTRAINT ck_suggestion_review CHECK ((status='new' AND response IS NULL AND reviewed_by IS NULL AND reviewed_at IS NULL) OR (status<>'new' AND response IS NOT NULL AND length(response) BETWEEN 10 AND 2000 AND reviewed_by IS NOT NULL AND reviewed_at IS NOT NULL))
);
CREATE INDEX IF NOT EXISTS ix_suggestion_reporter_created ON user_suggestions (reporter, created_at);
CREATE INDEX IF NOT EXISTS ix_suggestion_status_created ON user_suggestions (status, created_at);
-- migrate:down
DROP TABLE user_suggestions;
