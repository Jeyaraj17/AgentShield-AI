ALTER TABLE audit_events ADD COLUMN execution_id CHAR(36) NULL;
ALTER TABLE audit_events MODIFY COLUMN resource_identifier VARCHAR(500) NULL;
CREATE INDEX idx_audit_org_execution ON audit_events (organization_id, execution_id);
