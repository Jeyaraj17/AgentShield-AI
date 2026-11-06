CREATE TABLE runtime_executions (
    id CHAR(36) NOT NULL PRIMARY KEY,
    organization_id CHAR(36) NOT NULL,
    agent_id CHAR(36) NOT NULL,
    user_id CHAR(36) NOT NULL,
    action_identifier VARCHAR(150) NOT NULL,
    resource_identifier VARCHAR(500) NOT NULL,
    authorization_decision VARCHAR(8) NOT NULL,
    reason_code VARCHAR(80) NOT NULL,
    execution_result VARCHAR(20) NOT NULL,
    correlation_id CHAR(36) NOT NULL,
    created_at TIMESTAMP(6) NOT NULL,
    completed_at TIMESTAMP(6),
    CONSTRAINT ck_runtime_authorization_decision CHECK (authorization_decision IN ('ALLOW','DENY')),
    CONSTRAINT ck_runtime_execution_result CHECK (execution_result IN ('NOT_EXECUTED','PENDING','SUCCEEDED','FAILED'))
);

CREATE INDEX idx_runtime_execution_org_created ON runtime_executions (organization_id, created_at);
CREATE INDEX idx_runtime_execution_agent_created ON runtime_executions (agent_id, created_at);
