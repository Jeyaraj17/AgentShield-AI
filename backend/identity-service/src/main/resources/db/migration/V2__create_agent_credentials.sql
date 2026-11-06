CREATE TABLE agent_credentials (
    id CHAR(36) NOT NULL,
    client_id VARCHAR(100) NOT NULL,
    agent_id CHAR(36) NOT NULL,
    organization_id CHAR(36) NOT NULL,
    status VARCHAR(16) NOT NULL,
    created_at TIMESTAMP NOT NULL,
    revoked_at TIMESTAMP NULL,
    PRIMARY KEY (id),
    CONSTRAINT uk_agent_credentials_client_id UNIQUE (client_id),
    CONSTRAINT ck_agent_credentials_status CHECK (status IN ('ACTIVE', 'REVOKED'))
);
CREATE INDEX idx_agent_credentials_agent_org ON agent_credentials (agent_id, organization_id, status);
