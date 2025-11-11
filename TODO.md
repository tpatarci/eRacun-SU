# TODO - System Architecture Completion

**Status:** Pre-Implementation Planning Phase
**Created:** 2025-11-10
**Purpose:** Document architectural work required before bounded context implementation

---

## Overview

Before we can define business logic for individual bounded contexts, we need to establish the complete system-wide architecture. This document tracks the missing architectural artifacts and provides objectives, methodology, and rationale for each.

---

## 🔴 Priority 1: System-Wide Architecture (Blocking)

### TODO-001: Create Complete Service Catalog (Nodes)

**Status:** ✅ Complete
**Completed:** 2025-11-10

**Objective:**
- Produce an authoritative, exhaustive list of all bounded contexts in the eRacun platform
- Define single-responsibility statement for each context
- Categorize services by architectural layer (ingestion/validation/transformation/integration/infrastructure)
- Establish preliminary complexity estimates (LOC budget, team size)

**Methodology:**
1. **Domain Analysis:**
   - Map all business processes from CROATIAN_COMPLIANCE.md
   - Identify distinct responsibilities (invoice parsing, validation, transformation, submission, archiving)
   - Apply Domain-Driven Design bounded context identification patterns
   - Classify data ownership boundaries (source of truth per aggregate)

2. **Decomposition Strategy:**
   - Apply Single Responsibility Principle (each service = ONE clear purpose)
   - Enforce 2,500 LOC limit per service (CLAUDE.md section 2.2)
   - Ensure each context can fit in AI assistant context window
   - Group by business capability vs. technical layer
   - Record "service guardians" (accountable owners) to enforce stewardship

3. **Catalog Structure:**
   ```
   Service Name | Layer | Single Responsibility | Complexity | Dependencies
   ```

4. **Validation Criteria:**
   - No overlapping responsibilities between contexts
   - Clear input/output boundaries
   - Can be developed independently
   - Has measurable business value
   - Storage and regulatory responsibilities clearly enumerated

**Rationale:**

**Why Critical:**
- Without complete catalog, we risk:
  - Discovering missing services mid-implementation
  - Overlapping responsibilities between contexts
  - Unclear ownership of business logic
  - Integration gaps in processing pipelines

**Why Now:**
- Bounded context identification is foundational architectural work
- Must precede contract definition (contracts exist between contexts)
- Must precede edge definition (edges connect contexts)
- Prevents rework if contexts discovered late

**Architectural Impact:**
- Defines system decomposition strategy
- Establishes service ownership model
- Determines deployment topology
- Influences infrastructure sizing (# of systemd units, resources)

**Business Impact:**
- Clear service catalog enables accurate effort estimation
- Enables parallel team development
- Provides stakeholder visibility into system components

**Deliverable:**
- ADR-003 Section 1: Complete Service Catalog
- Table with all bounded contexts, responsibilities, complexity estimates
- Service dependency matrix (preliminary)
- Context map highlighting upstream/downstream relationships
- Stewardship roster (owner + escalation contacts)

---

### TODO-002: Define System-Wide Message Catalog (Contracts)

**Status:** ✅ Complete
**Completed:** 2025-11-10
**Depends On:** TODO-001

**Objective:**
- Create exhaustive catalog of all messages exchanged between bounded contexts
- Define Protocol Buffer schemas for every message type
- Establish message versioning strategy
- Document message taxonomy (Commands, Events, Queries)

**Methodology:**
1. **Message Discovery:**
   - For each bounded context pair, identify required communication
   - Apply Event Storming technique to discover domain events
   - Identify command messages (RPC-style, request/response)
   - Identify event messages (pub/sub, fire-and-forget)
   - Identify query messages (synchronous reads)

2. **Schema Definition:**
   - Use Protocol Buffers for all message schemas
   - Create `.proto` files in `/docs/api-contracts/protobuf/`
   - Follow naming conventions:
     - Commands: `{Verb}{Entity}Command` (e.g., `ValidateInvoiceCommand`)
     - Events: `{Entity}{PastTenseVerb}Event` (e.g., `InvoiceValidatedEvent`)
     - Queries: `Get{Entity}Query` (e.g., `GetInvoiceStatusQuery`)

3. **Message Patterns:**
   - **Commands** (RabbitMQ RPC): Direct service-to-service, requires response
   - **Events** (Kafka): Broadcast state changes, no response expected
   - **Queries** (gRPC): Synchronous reads, limited use

4. **Versioning Strategy:**
   - Use semantic versioning for Protobuf packages
   - Backward compatibility required for minor versions
   - Breaking changes require major version bump + migration plan
   - Maintain change log per schema with rationale and rollout strategy

5. **Catalog Structure:**
   ```
   Message Name | Type | Producer | Consumers | Purpose | Schema Version
   ```

6. **Verification:**
   - Create automated schema compatibility checks (buf, protovalidate)
   - Define contract-testing templates for commands, events, and queries
   - Capture sample payloads for integration smoke tests

**Rationale:**

**Why Critical:**
- Without message catalog, we risk:
  - Schema mismatches at runtime (type errors)
  - Breaking changes without migration strategy
  - Unclear message ownership (who publishes what)
  - Duplicate messages for same purpose

**Why Now:**
- Message contracts are the foundation of service integration
- Must be defined before implementing service business logic
- Changes to contracts after implementation = expensive refactoring
- Protocol Buffers provide compile-time type safety (prevents runtime errors)

**Architectural Impact:**
- Defines communication patterns (synchronous vs. asynchronous)
- Establishes data consistency model (eventual vs. strong)
- Influences message bus topology (queues, exchanges, topics)
- Determines backward compatibility requirements

**Business Impact:**
- Clear contracts enable parallel team development (no waiting for implementation)
- Reduces integration bugs (type-safe communication)
- Enables contract testing (verify compatibility before deployment)

**Deliverable:**
- ADR-003 Section 2: System-Wide Message Catalog
- Protocol Buffer schema files in `/docs/api-contracts/protobuf/`
- Message taxonomy document
- Versioning strategy guide
- Contract-testing playbook (tooling, CI integration)

---

### TODO-003: Map Integration Topology (Edges)

**Status:** ✅ Complete
**Completed:** 2025-11-10
**Depends On:** TODO-001, TODO-002

**Objective:**
- Create service dependency graph (which services call which)
- Define message routing topology (RabbitMQ exchanges, queues, routing keys)
- Document synchronous vs. asynchronous communication patterns
- Identify circular dependencies (anti-pattern to resolve)

**Methodology:**
1. **Dependency Graph Creation:**
   - For each bounded context, list upstream dependencies (services it calls)
   - For each bounded context, list downstream consumers (services that call it)
   - Use Graphviz/PlantUML to visualize dependency graph
   - Identify critical paths (longest dependency chains)
   - Annotate edges with latency/SLA expectations and data classification (PII/non-PII)

2. **Message Routing Design:**
   - **RabbitMQ Topology:**
     - Define exchanges (topic, direct, fanout)
     - Define queues (per service, per message type)
     - Define routing keys (message routing rules)
     - Define dead letter queues (error handling)
   - **Kafka Topology:**
     - Define topics (event categories)
     - Define partitioning strategy (ordering guarantees)
     - Define consumer groups (parallel processing)

3. **Communication Pattern Mapping:**
   - Synchronous: gRPC for request/response (queries, critical commands)
   - Asynchronous: RabbitMQ for commands (with acknowledgment)
   - Fire-and-forget: Kafka for events (no response needed)

4. **Circular Dependency Resolution:**
   - Identify any circular dependencies
   - Break cycles using:
     - Event-driven communication (pub/sub instead of RPC)
     - Mediator pattern (introduce orchestrator service)
     - Data duplication (eventual consistency)
   - Document trade-offs and risk mitigations for each resolved cycle

5. **Topology Diagrams:**
   - Service dependency graph (Graphviz)
   - Message flow diagram (sequence diagrams)
   - RabbitMQ topology diagram (exchanges, queues, bindings)
   - Kafka topic map (topics, partitions, consumer groups)
   - Resiliency overlay (fallback paths, circuit breakers, DLQs)

**Rationale:**

**Why Critical:**
- Without integration topology, we risk:
  - Circular dependencies (deadlocks, cascading failures)
  - Unclear message routing (lost messages, routing errors)
  - Performance bottlenecks (synchronous calls in critical paths)
  - Tight coupling between services (changes ripple across system)

**Why Now:**
- Integration topology must be defined before implementing service communication
- Message routing configuration is infrastructure setup (must exist before deployment)
- Circular dependencies are architectural flaws (easier to fix in design phase)
- Visualization helps identify anti-patterns early

**Architectural Impact:**
- Determines system scalability (async = better throughput)
- Influences failure isolation (sync calls = cascading failures)
- Establishes message delivery guarantees (at-least-once vs. exactly-once)
- Defines system observability (tracing across service boundaries)

**Business Impact:**
- Clear topology enables accurate performance modeling
- Identifies single points of failure
- Enables capacity planning (message volumes, queue depths)
- Provides operational visibility (which services are critical path)

**Deliverable:**
- ADR-003 Section 3: Integration Topology
- Service dependency graph diagram (Graphviz)
- RabbitMQ topology specification (exchanges, queues, routing keys)
- Kafka topic map (topics, partitions, consumer groups)
- Sequence diagrams for key workflows
- Resiliency playbook (fallback/circuit breaker plan)

---

### TODO-004: Specify Processing Pipelines

**Status:** ✅ Complete
**Completed:** 2025-11-10
**Depends On:** TODO-001, TODO-002, TODO-003

**Objective:**
- Define end-to-end invoice processing flows (B2C, B2B, B2G)
- Document error handling pipelines (DLQ, manual review, retry)
- Specify saga patterns for long-running transactions
- Establish idempotency and retry strategies

**Methodology:**
1. **Pipeline Identification:**
   - **B2C Invoice Pipeline:**
     - Email ingestion → Attachment extraction → OCR (if PDF/image) → XML parsing
     - → XSD validation → Schematron validation → KPD validation → Business rules
     - → UBL transformation → Digital signature → FINA SOAP submission
     - → Confirmation receipt → Archive storage

   - **B2B Invoice Pipeline:**
     - API upload → XML parsing → XSD validation → Schematron validation
     - → KPD validation → Business rules → UBL transformation
     - → Digital signature → AS4 gateway submission → Archive storage

   - **B2G Invoice Pipeline:**
     - Similar to B2B but with additional:
     - → Budget verification → Approval workflow → eRačun portal submission

   - **Error Handling Pipeline:**
     - Dead Letter Queue → Error classification → Manual review queue
     - → Correction workflow → Resubmission → Retry with backoff
     - → Post-incident review with root-cause analysis template

2. **Saga Pattern Design:**
   - Identify long-running transactions (multi-step processes that can fail partially)
   - Choose saga pattern:
     - **Choreography:** Event-driven, decentralized (each service knows next step)
     - **Orchestration:** Centralized coordinator service (workflow engine)
   - Define compensating transactions (rollback/undo operations)

3. **Idempotency Strategy:**
   - Every operation uses idempotency keys (invoice_id as primary key)
   - Duplicate requests produce identical results (no side effects)
   - State machines track processing stages (prevent partial completion)
   - Persist replay-safe audit log entries with immutable event history

4. **Retry Strategy:**
   - Transient failures: Exponential backoff with jitter (3 retries max)
   - Network errors: Retry with circuit breaker (prevent thundering herd)
   - Business validation errors: No retry (move to manual review)
   - Define human escalation paths when automated retries exhausted

5. **Pipeline Documentation:**
   - Swimlane diagrams (services across horizontal lanes, time flows down)
   - State transition diagrams (invoice lifecycle states)
   - Failure scenario documentation (what happens when each step fails)
   - Observability specification (metrics, traces, structured logs per stage)

**Rationale:**

**Why Critical:**
- Without pipeline specifications, we risk:
  - Partial processing (invoice stuck in intermediate state)
  - Data corruption (retries causing duplicate submissions)
  - Lost invoices (messages dropped, no error handling)
  - Unclear recovery procedures (manual intervention required)

**Why Now:**
- Pipelines define the "happy path" and error paths
- Saga patterns must be designed before implementation (hard to retrofit)
- Idempotency strategy affects database schema design (need idempotency keys)
- Error handling is cross-cutting concern (every service needs consistent approach)

**Architectural Impact:**
- Determines transaction boundaries (what must be atomic)
- Establishes consistency model (eventual consistency acceptable?)
- Defines system resilience (can recover from partial failures)
- Influences monitoring/alerting strategy (which stages to track)

**Business Impact:**
- Clear pipelines enable SLA definition (how long from upload to submission?)
- Error handling ensures no invoice is lost (regulatory compliance)
- Idempotency prevents duplicate tax submissions (financial correctness)
- Retry strategy balances reliability vs. cost (compute resources)

**Regulatory Impact:**
- Audit trail requirements (every stage logged with timestamps)
- Error preservation (failed invoices must be retained with error context)
- Reprocessing capability (manual correction workflow required by law)

**Deliverable:**
- ADR-003 Section 4: Processing Pipelines
- Swimlane diagrams for B2C, B2B, B2G flows
- State machine diagrams (invoice lifecycle)
- Saga pattern specifications (choreography vs. orchestration)
- Error handling flowcharts
- Idempotency and retry strategy documentation
- Observability runbook (alerts, dashboards, log taxonomy)

---

## 🟢 Priority 2: Supporting Documentation (Non-Blocking)

### TODO-005: Create Service Dependency Matrix

**Status:** ⏳ Not Started
**Depends On:** TODO-003

**Objective:**
- Produce matrix showing which services depend on which
- Identify services with high fan-in (many consumers = critical)
- Identify services with high fan-out (many dependencies = fragile)

**Methodology:**
- Create CSV/table: rows = services, columns = services
- Mark cells with dependency type (sync RPC, async message, event subscription)
- Calculate metrics (fan-in count, fan-out count)
- Include qualitative risk flags (e.g., regulatory, financial, security impact)
- Highlight latency-sensitive dependencies and required SLAs

**Rationale:**
- High fan-in services need extra reliability (many consumers affected by failures)
- High fan-out services are fragile (many points of failure)
- Matrix visualization helps identify architectural hotspots

**Deliverable:**
- Service dependency matrix (CSV + visualization)
- Analysis of critical services (high fan-in)
- Hotspot remediation backlog with suggested mitigations

---

### TODO-006: Document External System Integration Points

**Status:** ✅ Complete
**Completed:** 2025-11-10

**Objective:**
- Catalog all external systems (FINA SOAP API, AS4 gateways, DZS KLASUS registry)
- Document authentication requirements (X.509 certificates, API keys)
- Specify rate limits, timeouts, retry policies per external system

**Methodology:**
- List each external system with:
  - Endpoint URLs (test, production)
  - Authentication method
  - SLA/availability guarantees
  - Rate limits
  - Error response codes
- Create integration test plan for each external system
- Capture data residency/compliance requirements per integration
- Define credential rotation procedures and certificate renewal calendar

**Rationale:**
- External systems are outside our control (need defensive programming)
- Authentication complexity (X.509 certificates require lifecycle management)
- Rate limits affect scalability (must implement backpressure)

**Deliverable:**
- External integration catalog (markdown table)
- Integration test specifications per external system
- Credential lifecycle management checklist

---

### TODO-008: Define Cross-Cutting Concerns (Security, Observability, Compliance)

**Status:** ✅ Complete
**Completed:** 2025-11-10
**Depends On:** TODO-001 through TODO-004

**Objective:**
- Document shared architectural requirements that every bounded context must implement
- Standardize security controls (authentication, authorization, encryption)
- Establish observability baselines (metrics, logs, traces)
- Map regulatory requirements to technical controls (GDPR, Croatian e-invoice mandates)

**Methodology:**
1. **Security Architecture:**
   - Define service-to-service authentication (mTLS, JWT scopes)
   - Specify authorization patterns (ABAC vs. RBAC) and enforcement points
   - Catalog data classification levels and required encryption (in transit, at rest)
   - Document secrets management approach (Vault, KMS) and rotation cadence

2. **Observability Standards:**
   - Define required metrics per service (latency, throughput, error rates)
   - Standardize trace propagation (W3C Trace Context) and sampling strategy
   - Enumerate structured logging fields and retention policies
   - Establish alerting thresholds and on-call escalation procedures

3. **Compliance Mapping:**
   - Link CROATIAN_COMPLIANCE.md obligations to concrete controls/services
   - Define audit evidence requirements and reporting cadence
   - Identify data retention rules and deletion workflows
   - Ensure privacy impact assessment templates exist per bounded context

**Rationale:**
- Cross-cutting concerns, if left ad-hoc, cause inconsistent security posture and observability gaps
- Shared standards accelerate development and reduce operational toil
- Regulatory fines for non-compliance are material; proactive mapping mitigates risk

**Deliverable:**
- Cross-cutting concerns handbook (security, observability, compliance sections)
- Control matrix linking regulations to technical implementations
- Checklist to be embedded in Definition of Done for all services

---

## 🔵 Priority 3: Future Enhancements (Deferred)

### TODO-007: Evaluate Workflow Orchestration Engine

**Status:** ⏳ Not Started
**Deferred Until:** After initial pipeline implementation

**Objective:**
- Evaluate Temporal.io for complex saga orchestration
- Compare choreography vs. orchestration for long-running workflows

**Rationale:**
- Temporal provides workflow versioning, retry logic, observability
- But adds operational complexity (another component to run)
- Defer until we understand pain points with choreography approach

---

## Decision Log

### Why ADR-003 Instead of Multiple ADRs?

**Decision:** Combine service catalog, message catalog, integration topology, and pipelines into single ADR-003.

**Rationale:**
- These four artifacts are tightly coupled (changes to one affect others)
- Single document provides complete system-wide view
- Easier to maintain consistency (one source of truth)
- Enables holistic review (see entire integration architecture at once)

**Alternative Considered:** Separate ADRs (ADR-003, ADR-004, ADR-005, ADR-006)
**Rejected Because:** Too fragmented, hard to see complete picture, risk of inconsistencies

---

### Why Protocol Buffers for Message Schemas?

**Decision:** Use Protocol Buffers for all message schemas.

**Rationale:**
- Type-safe message serialization (compile-time errors instead of runtime)
- Backward compatibility built-in (field numbers enable schema evolution)
- Language-agnostic (can generate TypeScript, Python, Go clients)
- Compact binary format (smaller than JSON, faster parsing)
- gRPC native support (gRPC uses Protobuf by default)

**Alternative Considered:** JSON Schema
**Rejected Because:** No compile-time validation, larger payloads, no native gRPC support

---

### Why Event Storming for Message Discovery?

**Decision:** Use Event Storming technique to discover domain events.

**Rationale:**
- Domain-Driven Design technique (aligns with bounded context approach)
- Collaborative (involves business stakeholders, not just developers)
- Discovers events from business process perspective (not technical implementation)
- Identifies aggregate boundaries (helps define bounded contexts)

**Alternative Considered:** Bottom-up (implement services first, discover messages as needed)
**Rejected Because:** Leads to ad-hoc message design, inconsistent patterns, missed events

---

## Review Checklist

Before proceeding to bounded context implementation, verify:

- [x] **TODO-001 Complete:** All bounded contexts identified and documented
- [x] **TODO-002 Complete:** All message schemas defined in Protocol Buffers
- [x] **TODO-003 Complete:** Service dependency graph created, no circular dependencies
- [x] **TODO-004 Complete:** B2C, B2B, B2G pipelines fully specified with error handling
- [ ] **TODO-005 Complete:** Service dependency matrix analyzed and mitigation backlog created
- [x] **TODO-006 Complete:** External integration catalog finalized with credential lifecycle plan
- [x] **TODO-008 Complete:** Cross-cutting concern standards published and adopted
- [ ] **ADR-003 Approved:** System-wide integration architecture reviewed and approved
- [ ] **No architectural gaps:** All system-level design decisions documented
- [ ] **Confidence level:** Can implement any bounded context without system-level questions

---

**Last Updated:** 2025-11-10
**Owner:** System Architect
**Review Cadence:** After each TODO completion
