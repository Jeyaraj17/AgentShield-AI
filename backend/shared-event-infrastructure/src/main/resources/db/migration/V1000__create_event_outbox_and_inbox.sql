CREATE TABLE event_outbox (
  event_id CHAR(36) PRIMARY KEY,
  organization_id CHAR(36) NOT NULL,
  event_type VARCHAR(80) NOT NULL,
  routing_key VARCHAR(120) NOT NULL,
  schema_version INTEGER NOT NULL,
  payload_json TEXT NOT NULL,
  status VARCHAR(16) NOT NULL,
  attempts INTEGER NOT NULL DEFAULT 0,
  available_at TIMESTAMP(6) NOT NULL,
  locked_until TIMESTAMP(6),
  created_at TIMESTAMP(6) NOT NULL,
  published_at TIMESTAMP(6),
  last_error_code VARCHAR(80)
);
CREATE INDEX idx_event_outbox_ready ON event_outbox(status, available_at);
CREATE INDEX idx_event_outbox_org_created ON event_outbox(organization_id, created_at);
CREATE TABLE event_inbox (
  event_id CHAR(36) PRIMARY KEY,
  organization_id CHAR(36) NOT NULL,
  event_type VARCHAR(80) NOT NULL,
  payload_json TEXT NOT NULL,
  received_at TIMESTAMP(6) NOT NULL,
  processed_at TIMESTAMP(6) NOT NULL
);
CREATE INDEX idx_event_inbox_org_received ON event_inbox(organization_id, received_at);
