CREATE TABLE audit_events (
  event_id CHAR(36) NOT NULL,
  organization_id CHAR(36) NOT NULL,
  event_type VARCHAR(48) NOT NULL,
  actor_identity VARCHAR(100) NOT NULL,
  actor_type VARCHAR(16) NOT NULL,
  agent_id CHAR(36),
  action_name VARCHAR(160),
  resource_identifier VARCHAR(160),
  decision VARCHAR(16),
  reason VARCHAR(100),
  execution_outcome VARCHAR(20),
  correlation_id CHAR(36) NOT NULL,
  event_timestamp TIMESTAMP(6) NOT NULL,
  received_timestamp TIMESTAMP(6) NOT NULL,
  CONSTRAINT pk_audit_events PRIMARY KEY (event_id)
);
CREATE INDEX idx_audit_org_time ON audit_events (organization_id, event_timestamp);
CREATE INDEX idx_audit_org_type_time ON audit_events (organization_id, event_type, event_timestamp);
CREATE INDEX idx_audit_org_agent_time ON audit_events (organization_id, agent_id, event_timestamp);
CREATE INDEX idx_audit_org_outcome_time ON audit_events (organization_id, execution_outcome, event_timestamp);
