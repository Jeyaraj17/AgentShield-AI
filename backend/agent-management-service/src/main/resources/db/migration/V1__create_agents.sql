CREATE TABLE agents (
    id CHAR(36) NOT NULL,
    organization_id CHAR(36) NOT NULL,
    agent_name VARCHAR(150) NOT NULL,
    agent_code VARCHAR(50) NOT NULL,
    description VARCHAR(1000) NULL,
    agent_type VARCHAR(50) NOT NULL,
    status VARCHAR(16) NOT NULL,
    capabilities JSON NOT NULL,
    created_at TIMESTAMP(6) NOT NULL,
    updated_at TIMESTAMP(6) NOT NULL,
    CONSTRAINT pk_agents PRIMARY KEY (id),
    CONSTRAINT uk_agents_organization_code UNIQUE (organization_id, agent_code)
);

CREATE INDEX idx_agents_organization_id ON agents (organization_id);
CREATE INDEX idx_agents_organization_status ON agents (organization_id, status);
