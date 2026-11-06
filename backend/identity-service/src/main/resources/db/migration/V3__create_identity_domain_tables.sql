CREATE TABLE organizations (
    id BINARY(16) NOT NULL,
    name VARCHAR(150) NOT NULL,
    organization_code VARCHAR(50) NOT NULL,
    description VARCHAR(500) NULL,
    status VARCHAR(16) NOT NULL,
    created_at TIMESTAMP(6) NOT NULL,
    updated_at TIMESTAMP(6) NOT NULL,
    CONSTRAINT pk_organizations PRIMARY KEY (id),
    CONSTRAINT uk_organizations_organization_code UNIQUE (organization_code)
);

CREATE TABLE users (
    id BINARY(16) NOT NULL,
    email_normalized VARCHAR(254) NOT NULL,
    first_name VARCHAR(100) NOT NULL,
    last_name VARCHAR(100) NOT NULL,
    password_hash VARCHAR(100) NOT NULL,
    status VARCHAR(16) NOT NULL,
    created_at TIMESTAMP(6) NOT NULL,
    updated_at TIMESTAMP(6) NOT NULL,
    CONSTRAINT pk_users PRIMARY KEY (id),
    CONSTRAINT uk_users_email_normalized UNIQUE (email_normalized)
);

CREATE TABLE organization_memberships (
    id BINARY(16) NOT NULL,
    user_id BINARY(16) NOT NULL,
    organization_id BINARY(16) NOT NULL,
    organization_role VARCHAR(16) NOT NULL,
    membership_status VARCHAR(16) NOT NULL,
    joined_at TIMESTAMP(6) NOT NULL,
    CONSTRAINT pk_organization_memberships PRIMARY KEY (id),
    CONSTRAINT uk_membership_user_organization UNIQUE (user_id, organization_id),
    CONSTRAINT fk_membership_user FOREIGN KEY (user_id) REFERENCES users (id),
    CONSTRAINT fk_membership_organization FOREIGN KEY (organization_id) REFERENCES organizations (id)
);

CREATE INDEX idx_membership_organization_id ON organization_memberships (organization_id);
