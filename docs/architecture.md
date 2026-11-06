# AgentShield AI Architecture

## 1. Purpose and scope

AgentShield AI is an enterprise platform for managing AI agents, applying security policies, inspecting agent activity, recording security events, and notifying operators. The system consists of six business microservices, two gateway components, a React administration dashboard, and supporting infrastructure.

This document records the approved architecture baseline. The six business microservices remain distinct and retain the responsibilities below.

## 2. High-level topology

```text
Enterprise users
       |
       v
React Admin Dashboard
       |
       v
Spring Cloud API Gateway ----> Identity Service
       |                         Agent Management Service
       |                         Policy Engine Service
       |                         AI Analysis Service
       |                         Audit Service
       |                         Notification Service
       |
       +---- Platform management APIs

External AI agents
       |
       v
Runtime Security Gateway
       |  identity and tenant resolution
       |  registered destination validation
       |  deterministic authorization request
       |  fail-closed enforcement and proxying
       +---------------------> Approved tool/action destination
       |
       +---------------------> Policy Engine Service

Services <---- RabbitMQ events ----> Services
Services ---- owned data stores ----> MySQL 8
AI Analysis Service ---- Spring AI ----> External LLM providers
```

The diagram is logical. Network topology, deployment units, and concrete API contracts are to be specified during implementation without changing the approved component responsibilities.

## 3. Business microservices

### 3.1 Identity Service

Owns organization and user management, organization memberships, role-based access, and authentication identity. It issues and validates JWTs and manages the lifecycle of AI agent credentials. Trusted identity and organization context originate from this service's authentication flows.

### 3.2 Agent Management Service

Registers and manages AI agents. It maintains agent profiles, metadata, status, capabilities, configurations, organization associations, and lifecycle information. It owns the authoritative management records for registered agents.

### 3.3 Policy Engine Service

Creates and manages security policies, including policy versions and assignments. It defines resource permissions and access rules and returns deterministic `ALLOW` or `DENY` authorization decisions. It is the final authorization authority for protected operations.

### 3.4 AI Analysis Service

Analyzes prompts and agent requests to detect prompt injection, potential threats, and sensitive data exposure. It produces risk assessments and security recommendations and can run controlled attack simulations against test agents. It may use Spring AI to integrate with external LLM providers.

AI output is advisory. The AI Analysis Service must never make, replace, or override a final authorization decision. Authorization is performed deterministically by the Policy Engine Service.

### 3.5 Audit Service

Consumes security events from RabbitMQ and persists security audit records. It maintains authorization decision history separately from execution history and provides audit search and reporting for compliance and security investigations.

### 3.6 Notification Service

Consumes relevant security events, generates security alerts and notifications, manages notification delivery, and maintains notification history and delivery status.

## 4. Gateways and user interface

### Spring Cloud API Gateway

The API Gateway is the entry point for platform management APIs and routes requests to the appropriate business services. It integrates with trusted authentication and passes verified identity and tenant context through the platform boundary. Downstream services still enforce authorization and tenant-scoped access; gateway routing alone is not an authorization grant.

### Runtime Security Gateway

The Runtime Security Gateway intercepts external AI agent tool and action requests. It validates agent identity, resolves tenant context from trusted authentication, verifies requested destinations against registered tool destinations, obtains an authorization decision from the Policy Engine Service, enforces that decision, and proxies only approved requests.

The Runtime Security Gateway must fail closed: if identity, tenant context, destination validation, or authorization cannot be established, the request is denied. It must not infer an `ALLOW` decision from AI analysis, service unavailability, or missing policy results.

### React Admin Dashboard

The React dashboard provides enterprise management and monitoring capabilities for authorized users. It accesses platform management APIs through the Spring Cloud API Gateway. Every operation remains subject to server-side identity, tenant isolation, and authorization checks.

## 5. Supporting infrastructure

- **MySQL 8:** Persistent storage. Each business microservice owns its data and schema boundary; no service directly reads or writes another service's database tables.
- **RabbitMQ:** Asynchronous communication for security and other domain events. Event-producing services use a transactional outbox, and consumers are idempotent to handle retries and duplicate delivery safely.
- **Spring AI and external LLM providers:** Used by the AI Analysis Service for analysis capabilities. Provider output remains untrusted advisory input and cannot grant access.

Operational deployment, observability, secrets management, and environment-specific infrastructure must support these boundaries and must not introduce cross-service data access.

## 6. Enterprise tenancy and isolation

- The tenant boundary is the organization. Every organization-owned operation and record is scoped to the authenticated organization.
- Tenant context comes from trusted authentication and verified credentials. A request-supplied organization or tenant ID is not authoritative and must not select or elevate tenant context.
- Services validate and enforce tenant scope on every applicable read, write, event, and administrative action. Cross-tenant access is denied by default.
- Tenant identity is propagated across trusted service boundaries and included in event handling where needed to preserve isolation and auditability.
- Service-owned data, caches, and event consumers must preserve organization-level isolation. No microservice bypasses another service's API to access its data.
- Elevated or platform-wide administration requires explicit, separately authorized controls and auditable access; it must not arise from an absent tenant context.

## 7. Authorization and runtime security

The Policy Engine Service is the final authority for deterministic authorization decisions. The Runtime Security Gateway enforces those decisions for intercepted agent actions. Other services must also enforce their applicable server-side access rules. AI analysis can inform human review or policy workflows, but cannot grant, deny, or override access.

Runtime tool/action requests are permitted only after the gateway has validated agent identity and tenant context, verified the destination, and received an explicit `ALLOW` from the Policy Engine. Any missing, invalid, or unavailable prerequisite results in denial.

## 8. Reliability and auditability

Event-producing services use the transactional outbox pattern so committed business changes and corresponding events are recorded reliably. RabbitMQ consumers are idempotent and tolerate redelivery. Security events and authorization decisions are auditable, and the Audit Service keeps authorization decision history distinct from execution history to support investigation and compliance needs.
