# Development Roadmap

This roadmap implements the approved AgentShield AI architecture in twelve phases. The six business microservices remain distinct, organization-level tenant isolation is enforced throughout, the Policy Engine remains the final authorization authority, and AI analysis remains advisory. Runtime Security Gateway enforcement must fail closed.

## Phase 1 — Architecture and SRS finalization

- Finalize the system architecture, service responsibilities, interfaces, and trust boundaries.
- Complete the Software Requirements Specification (SRS), including functional, security, tenancy, audit, reliability, and operational requirements.
- Confirm acceptance criteria and traceability for the approved six-service architecture.

## Phase 2 — Repository and project foundation

- Establish repository structure, development conventions, build and release workflows, and environment strategy.
- Set up approved platform foundations for service execution, persistence, messaging, secrets, and observability.
- Establish secure service identity and baseline health and operational reporting.

## Phase 3 — Identity Service

- Implement organization and user management, memberships, and role-based access.
- Implement authentication identity, JWT generation and validation, and AI agent credential lifecycle management.
- Establish trusted organization context for tenant isolation.

## Phase 4 — Agent Management Service

- Implement agent registration and management.
- Maintain agent profiles, metadata, status, capabilities, configurations, organization association, and lifecycle information.
- Enforce tenant-scoped access to agent records.

## Phase 5 — Policy Engine

- Implement policy creation and management, policy versions and assignments, resource permissions, and access rules.
- Provide deterministic `ALLOW`/`DENY` authorization decisions and remain the final authorization authority.
- Keep authorization independent of AI-generated recommendations.

## Phase 6 — Spring Cloud API Gateway

- Implement the platform management API entry point and routing to the business services.
- Integrate trusted authentication and propagate verified identity and tenant context.
- Preserve service-side authorization and tenant enforcement; gateway routing alone does not grant access.

## Phase 7 — Runtime Security Gateway

- Intercept external AI agent tool and action requests.
- Validate agent identity, resolve trusted tenant context, and check destinations against registered tools.
- Obtain and enforce Policy Engine decisions, proxy only explicitly allowed requests, and fail closed on errors or missing decisions.

## Phase 8 — AI Analysis and attack simulation

- Implement prompt and agent-request analysis for prompt injection, threats, and sensitive data exposure.
- Produce risk assessments and security recommendations using Spring AI and external LLM providers where appropriate.
- Add controlled attack simulations against test agents.
- Keep AI output advisory; it cannot make or override final authorization decisions.

## Phase 9 — RabbitMQ and reliable event processing

- Establish RabbitMQ event flows for relevant domain and security events.
- Implement the transactional outbox pattern for reliable publication of committed changes.
- Make event consumers idempotent and safe under retries and duplicate delivery.
- Preserve tenant context and isolation in event production and consumption.

## Phase 10 — Audit and Notification Services

- Implement the Audit Service to consume security events, persist audit records, and support search and reporting.
- Maintain authorization decision history separately from execution history.
- Implement the Notification Service to consume relevant events, deliver alerts, and track notification history and delivery status.

## Phase 11 — React frontend

- Implement the enterprise administration and monitoring dashboard in React.
- Integrate through the Spring Cloud API Gateway using documented APIs.
- Apply tenant-aware presentation while relying on server-side authorization for every operation.
- Present AI findings as advisory information with clear provenance.

## Phase 12 — Integration, security testing and deployment

- Integrate all services, gateways, event flows, persistence, and the React frontend.
- Verify functional contracts, tenant isolation, authorization, runtime fail-closed behavior, audit trails, and reliable event processing.
- Complete security, resilience, performance, and operational readiness reviews.
- Deploy progressively through approved environments with monitoring and rollback criteria.
