CREATE TABLE analysis_records (
    id CHAR(36) NOT NULL PRIMARY KEY,
    organization_id CHAR(36) NOT NULL,
    agent_id CHAR(36) NOT NULL,
    analysis_type VARCHAR(40) NOT NULL,
    risk_score INT,
    result_json TEXT NOT NULL,
    created_at TIMESTAMP(6) NOT NULL,
    INDEX idx_analysis_tenant_agent_type_created (organization_id, agent_id, analysis_type, created_at),
    INDEX idx_analysis_tenant_created (organization_id, created_at)
);

CREATE TABLE behavior_observations (
    id CHAR(36) NOT NULL PRIMARY KEY,
    organization_id CHAR(36) NOT NULL,
    agent_id CHAR(36) NOT NULL,
    tool_call_count INT NOT NULL,
    error_count INT NOT NULL,
    policy_violation_count INT NOT NULL,
    unusual_activity_count INT NOT NULL,
    action_distribution_json TEXT NOT NULL,
    drift_score INT NOT NULL,
    drift_detected BOOLEAN NOT NULL,
    created_at TIMESTAMP(6) NOT NULL,
    INDEX idx_behavior_tenant_agent_created (organization_id, agent_id, created_at)
);
