CREATE TABLE security_policies (
    id CHAR(36) NOT NULL PRIMARY KEY,
    policy_id CHAR(36) NOT NULL,
    organization_id CHAR(36) NOT NULL,
    policy_name VARCHAR(150) NOT NULL,
    description VARCHAR(1000),
    version_number INT NOT NULL,
    status VARCHAR(16) NOT NULL,
    priority INT NOT NULL,
    is_latest BOOLEAN NOT NULL,
    created_at TIMESTAMP(6) NOT NULL,
    updated_at TIMESTAMP(6) NOT NULL,
    CONSTRAINT uk_policy_org_key_version UNIQUE (organization_id, policy_id, version_number)
);
CREATE INDEX idx_policies_org_latest ON security_policies (organization_id, is_latest);
CREATE INDEX idx_policies_org_policy ON security_policies (organization_id, policy_id, version_number);

CREATE TABLE policy_rules (
    id CHAR(36) NOT NULL PRIMARY KEY,
    policy_version_id CHAR(36) NOT NULL,
    rule_name VARCHAR(150) NOT NULL,
    agent_scope VARCHAR(20) NOT NULL,
    target_agent_id CHAR(36),
    action_identifier VARCHAR(150) NOT NULL,
    effect VARCHAR(8) NOT NULL,
    conditions JSON,
    created_at TIMESTAMP(6) NOT NULL,
    CONSTRAINT fk_policy_rules_version FOREIGN KEY (policy_version_id) REFERENCES security_policies(id)
);
CREATE INDEX idx_policy_rules_version ON policy_rules (policy_version_id);
CREATE INDEX idx_policy_rules_target_agent ON policy_rules (target_agent_id);
