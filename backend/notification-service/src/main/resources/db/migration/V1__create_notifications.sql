CREATE TABLE notifications (
  notification_id CHAR(36) NOT NULL,
  event_id CHAR(36) NOT NULL,
  organization_id CHAR(36) NOT NULL,
  category VARCHAR(40) NOT NULL,
  severity VARCHAR(16) NOT NULL,
  title VARCHAR(160) NOT NULL,
  description VARCHAR(500) NOT NULL,
  source_event_type VARCHAR(48) NOT NULL,
  agent_id CHAR(36),
  execution_id CHAR(36),
  source_identifier VARCHAR(180),
  correlation_id CHAR(36) NOT NULL,
  event_timestamp TIMESTAMP(6) NOT NULL,
  created_at TIMESTAMP(6) NOT NULL,
  read_at TIMESTAMP(6),
  CONSTRAINT pk_notifications PRIMARY KEY (notification_id),
  CONSTRAINT uk_notifications_event UNIQUE (event_id)
);
CREATE INDEX idx_notification_org_created ON notifications (organization_id, created_at);
CREATE INDEX idx_notification_org_read_created ON notifications (organization_id, read_at, created_at);
CREATE INDEX idx_notification_org_category_created ON notifications (organization_id, category, created_at);
CREATE INDEX idx_notification_org_agent_created ON notifications (organization_id, agent_id, created_at);
