# CLAUDE.md - Admin Portal API Service

**Service:** `admin-portal-api`
**Layer:** Management (Layer 10)
**Implementation Status:** 🔴 Not Started
**Your Mission:** Implement this service from specification to production-ready

---

## 1. YOUR MISSION

You are implementing the **admin-portal-api** service for the eRacun e-invoice processing platform. This service is the **backend for the administrative web portal**, aggregating data from all services for human operators.

**What you're building:**
- REST API backend (user management, manual review, reporting, configuration)
- JWT authentication + RBAC authorization (admin, operator, viewer roles)
- Multi-service data aggregator (queries audit-logger, health-monitor, dead-letter-handler, etc.)
- User session management (login/logout/token refresh)

**Estimated effort:** 4-5 days
**Complexity:** Medium (~2,000 LOC)

---

## 2. REQUIRED READING (Read in Order)

**Before writing any code, read these documents:**

1. **`README.md`** (in this directory) - Complete service specification
2. **`/CLAUDE.md`** (repository root) - System architecture and standards
3. **`/docs/TODO-008-cross-cutting-concerns.md`** - Observability requirements (MANDATORY)
4. **`/services/xsd-validator/`** - Reference implementation pattern
5. **`/services/schematron-validator/`** - Reference observability module
6. **`/services/audit-logger/README.md`** - gRPC audit trail queries
7. **`/services/health-monitor/README.md`** - Health dashboard data
8. **`/services/dead-letter-handler/README.md`** - Manual review queue

**Time investment:** 45-60 minutes reading
**Why mandatory:** Prevents rework, ensures compliance, establishes patterns

---

## 3. ARCHITECTURAL CONTEXT

### 3.1 Where This Service Fits

```
            ┌────────────────────┐
            │  Admin Portal UI   │
            │  (React/Vue/       │
            │   Angular SPA)     │
            └────────┬───────────┘
                     │
                     │ HTTP REST API (JWT auth)
                     ▼
            ┌────────────────────┐
            │  THIS SERVICE      │
            │  admin-portal-api  │
            └────────┬───────────┘
                     │
        ┌────────────┼────────────┬────────────┐
        │            │            │            │
        ▼            ▼            ▼            ▼
  audit-logger  health-    dead-letter-  cert-
  (gRPC)        monitor    handler       lifecycle-
                (HTTP)     (HTTP)        manager
                                          (HTTP)
                     │
                     │ Own database
                     ▼
            ┌────────────────────┐
            │  PostgreSQL        │
            │  admin_portal      │
            │  (users, sessions) │
            └────────────────────┘
```

### 3.2 Critical Dependencies

**Upstream (Consumes From):**
- Admin Portal UI (React/Vue/Angular) - HTTP REST API calls

**Downstream (Queries):**
- `audit-logger` (gRPC): Query audit trails
- `health-monitor` (HTTP): System health status
- `dead-letter-handler` (HTTP): Manual review queue
- `cert-lifecycle-manager` (HTTP): Certificate inventory
- `kpd-registry-sync` (gRPC): KPD code lookups
- `archive-service` (HTTP): Retrieve archived invoices (future)

**Own PostgreSQL Database:**
- `admin_portal` database (users, roles, permissions, sessions)

**No RabbitMQ queues** (HTTP API only, not message-driven)

### 3.3 Database Schema

**Users & Sessions:**

```sql
CREATE TABLE users (
  id BIGSERIAL PRIMARY KEY,
  email VARCHAR(255) UNIQUE NOT NULL,
  password_hash VARCHAR(255) NOT NULL,  -- bcrypt
  role VARCHAR(50) NOT NULL,            -- admin, operator, viewer
  active BOOLEAN DEFAULT true,
  created_at TIMESTAMP DEFAULT NOW(),
  last_login TIMESTAMP
);

CREATE TABLE sessions (
  id UUID PRIMARY KEY,
  user_id BIGINT NOT NULL REFERENCES users(id),
  token VARCHAR(512) NOT NULL,
  expires_at TIMESTAMP NOT NULL,
  created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_sessions_token ON sessions(token);
CREATE INDEX idx_sessions_user ON sessions(user_id);
```

---

## 4. IMPLEMENTATION WORKFLOW

**Follow this sequence strictly:**

### Phase 1: Setup (Day 1, Morning)

1. **Create package.json**
   ```bash
   npm init -y
   npm install --save express jsonwebtoken bcrypt pg axios @grpc/grpc-js cors helmet express-rate-limit prom-client pino opentelemetry
   npm install --save-dev typescript @types/node @types/express @types/jsonwebtoken @types/bcrypt jest @types/jest ts-jest
   ```

2. **Create tsconfig.json** (strict mode)
   ```json
   {
     "compilerOptions": {
       "target": "ES2022",
       "module": "commonjs",
       "strict": true,
       "esModuleInterop": true,
       "outDir": "./dist"
     }
   }
   ```

3. **Create directory structure**
   ```
   src/
   ├── index.ts              # Main server
   ├── auth/
   │   ├── middleware.ts     # JWT authentication middleware
   │   ├── rbac.ts           # Role-based access control
   │   └── routes.ts         # Auth endpoints (/login, /logout, /refresh)
   ├── users/
   │   ├── controller.ts     # User management logic
   │   ├── repository.ts     # PostgreSQL user queries
   │   └── routes.ts         # User endpoints
   ├── errors/
   │   ├── controller.ts     # Manual review logic
   │   └── routes.ts
   ├── invoices/
   │   ├── controller.ts     # Invoice search/retrieval
   │   └── routes.ts
   ├── health/
   │   ├── controller.ts     # Health dashboard aggregation
   │   └── routes.ts
   ├── reports/
   │   ├── controller.ts     # Report generation
   │   └── routes.ts
   ├── certificates/
   │   ├── controller.ts     # Certificate management
   │   └── routes.ts
   ├── clients/              # HTTP/gRPC clients for other services
   │   ├── audit-logger.ts
   │   ├── health-monitor.ts
   │   ├── dead-letter-handler.ts
   │   └── cert-lifecycle-manager.ts
   └── observability.ts
   tests/
   ├── setup.ts
   ├── unit/
   │   ├── auth.test.ts
   │   ├── rbac.test.ts
   │   └── observability.test.ts
   └── integration/
       ├── auth-flow.test.ts
       ├── user-management.test.ts
       └── manual-review.test.ts
   ```

### Phase 2: Core Implementation (Day 1 Afternoon - Day 3)

1. **Implement observability.ts FIRST** (TODO-008 compliance)
   - Copy pattern from `/services/xsd-validator/src/observability.ts`
   - Define 4+ Prometheus metrics (see README.md Section 7)
   - Structured logging (Pino)
   - Distributed tracing (OpenTelemetry)
   - PII masking (email addresses in logs)

2. **Implement auth/middleware.ts** (JWT authentication)
   - `authenticateJWT(req, res, next)` - Verify JWT token
   - `requireRole(...roles)` - RBAC authorization
   - Token validation:
     ```typescript
     import jwt from 'jsonwebtoken';

     export function authenticateJWT(req, res, next) {
       const token = req.headers.authorization?.split(' ')[1];

       if (!token) {
         return res.status(401).json({ error: 'Unauthorized' });
       }

       try {
         const user = jwt.verify(token, process.env.JWT_SECRET!);
         req.user = user;
         next();
       } catch (err) {
         return res.status(403).json({ error: 'Invalid token' });
       }
     }
     ```

3. **Implement auth/rbac.ts** (Role-based access control)
   - `requireRole(...roles: string[])` middleware
   - Roles: `admin`, `operator`, `viewer`
   - Example:
     ```typescript
     export function requireRole(...roles: string[]) {
       return (req, res, next) => {
         if (!roles.includes(req.user.role)) {
           return res.status(403).json({ error: 'Insufficient permissions' });
         }
         next();
       };
     }
     ```

4. **Implement auth/routes.ts** (Authentication endpoints)
   - POST `/api/v1/auth/login` - Login (email/password) → JWT token
   - POST `/api/v1/auth/logout` - Logout (invalidate token)
   - POST `/api/v1/auth/refresh` - Refresh JWT token
   - GET `/api/v1/auth/me` - Get current user info
   - Password hashing: bcrypt (cost factor: 12)

5. **Implement users/repository.ts** (PostgreSQL user operations)
   - Connection pool (min: 10, max: 50)
   - `createUser(email, password, role): Promise<User>`
   - `getUserByEmail(email): Promise<User | null>`
   - `getUserById(id): Promise<User | null>`
   - `updateUser(id, updates): Promise<void>`
   - `deactivateUser(id): Promise<void>`
   - `getAllUsers(): Promise<User[]>`

6. **Implement users/routes.ts** (User management endpoints)
   - GET `/api/v1/users` - List all users (admin only)
   - POST `/api/v1/users` - Create new user (admin only)
   - GET `/api/v1/users/:id` - Get user details (admin only)
   - PATCH `/api/v1/users/:id` - Update user (admin only)
   - DELETE `/api/v1/users/:id` - Deactivate user (admin only)

7. **Implement errors/controller.ts** (Manual error review)
   - Query dead-letter-handler HTTP API
   - Endpoints:
     - GET `/api/v1/errors` - List errors in manual review
     - GET `/api/v1/errors/:id` - Get error details
     - POST `/api/v1/errors/:id/resolve` - Mark as resolved
     - POST `/api/v1/errors/:id/resubmit` - Resubmit to original queue
     - POST `/api/v1/errors/bulk-resolve` - Bulk resolve

8. **Implement invoices/controller.ts** (Invoice management)
   - Query audit-logger gRPC API
   - Endpoints:
     - GET `/api/v1/invoices` - Search invoices (filters: date, OIB, status)
     - GET `/api/v1/invoices/:id` - Get invoice details
     - GET `/api/v1/invoices/:id/audit` - Get audit trail
     - GET `/api/v1/invoices/:id/xml` - Download original XML
     - POST `/api/v1/invoices/:id/reprocess` - Reprocess failed invoice

9. **Implement health/controller.ts** (Health dashboard)
   - Query health-monitor HTTP API
   - Aggregate data from all services
   - Endpoints:
     - GET `/api/v1/health/dashboard` - System-wide health
     - GET `/api/v1/health/services` - All services status
     - GET `/api/v1/health/external` - External dependencies
     - GET `/api/v1/health/circuit-breakers` - Circuit breaker states

10. **Implement reports/controller.ts** (Reporting)
    - Generate reports from aggregated data
    - Endpoints:
      - GET `/api/v1/reports/monthly` - Monthly invoice summary
      - GET `/api/v1/reports/errors` - Error statistics
      - GET `/api/v1/reports/submissions` - Submission rates

11. **Implement certificates/controller.ts** (Certificate management)
    - Query cert-lifecycle-manager HTTP API
    - Endpoints:
      - GET `/api/v1/certificates` - List certificates
      - POST `/api/v1/certificates/upload` - Upload new certificate
      - GET `/api/v1/certificates/expiring` - Expiring certificates

12. **Implement clients/** (HTTP/gRPC clients)
    - `audit-logger.ts` - gRPC client for audit trail queries
    - `health-monitor.ts` - HTTP client for health data
    - `dead-letter-handler.ts` - HTTP client for manual review
    - `cert-lifecycle-manager.ts` - HTTP client for certificates

13. **Implement index.ts** (Main entry point)
    - Express server (port 8089)
    - CORS configuration (whitelist admin portal frontend)
    - Helmet security headers
    - Rate limiting (login: 5/15min, API: 100/min)
    - Start Prometheus metrics endpoint (port 9094)
    - Health check endpoint (GET /health, GET /ready)
    - Graceful shutdown (SIGTERM, SIGINT)

### Phase 3: Testing (Day 3-4)

1. **Create test fixtures**
   - `tests/fixtures/users.json` (sample users)
   - Mock HTTP servers (nock or similar)
   - Mock gRPC clients
   - Testcontainers for PostgreSQL

2. **Write unit tests** (70% of suite)
   - `auth.test.ts`: JWT generation, validation
   - `rbac.test.ts`: Role-based access control
   - `observability.test.ts`: Metrics, logging (PII masking)
   - Target: 90%+ coverage for critical paths

3. **Write integration tests** (25% of suite)
   - `auth-flow.test.ts`: Login → token → authenticated request
   - `user-management.test.ts`: CRUD users
   - `manual-review.test.ts`: List/resolve/resubmit errors

4. **Run tests**
   ```bash
   npm test -- --coverage
   ```
   - **MUST achieve 85%+ coverage** (enforced in jest.config.js)

### Phase 4: Documentation (Day 4-5)

1. **Create RUNBOOK.md** (operations guide)
   - Copy structure from `/services/schematron-validator/RUNBOOK.md`
   - Sections: Deployment, Monitoring, Common Issues, Troubleshooting, Disaster Recovery
   - Scenarios:
     - Service dependencies unavailable (health-monitor, dead-letter-handler)
     - JWT secret rotation
     - User locked out (password reset)
     - Rate limiting triggered
   - Minimum 8 operational scenarios documented

2. **Create .env.example**
   - All environment variables documented
   - Include: DATABASE_URL, JWT_SECRET, SERVICE_URLS (health-monitor, dead-letter-handler, etc.)

3. **Create Dockerfile**
   - Multi-stage build (build → production)
   - Security: Run as non-root user, minimal base image

4. **Create systemd unit file** (`admin-portal-api.service`)
   - Security hardening: ProtectSystem=strict, NoNewPrivileges=true
   - Restart policy: always, RestartSec=10
   - Copy from `/services/xsd-validator/*.service`

5. **Create completion report**
   - File: `/docs/reports/{date}-admin-portal-api-completion.md`
   - Template: `/docs/reports/2025-11-11-schematron-validator-completion.md`
   - Sections: Executive Summary, Deliverables, Git Status, Traceability, Next Steps

### Phase 5: Commit & Push (Day 5)

1. **Commit all work**
   ```bash
   git add services/admin-portal-api/
   git commit -m "feat(admin-portal-api): implement admin portal backend with JWT auth and RBAC"
   ```

2. **Push to branch**
   ```bash
   git push -u origin claude/admin-portal-api-{your-session-id}
   ```

---

## 5. QUALITY STANDARDS (Non-Negotiable)

### 5.1 Code Quality

- ✅ **TypeScript strict mode** (no `any` types)
- ✅ **ESLint + Prettier** compliant
- ✅ **85%+ test coverage** (enforced in jest.config.js)
- ✅ **All errors explicitly handled** (no swallowed exceptions)

### 5.2 Security

- ✅ **No secrets in code** (use environment variables)
- ✅ **JWT secret rotation** (documented in RUNBOOK)
- ✅ **Password hashing** (bcrypt, cost factor 12)
- ✅ **Rate limiting** (login: 5/15min, API: 100/min)
- ✅ **CORS whitelist** (admin portal frontend domain only)
- ✅ **Helmet security headers** (CSP, X-Frame-Options, etc.)
- ✅ **PII masking in logs** (email addresses)
- ✅ **systemd security hardening** (ProtectSystem=strict, etc.)

### 5.3 Observability (TODO-008 Compliance)

**MANDATORY - Your service MUST include:**

- ✅ **4+ Prometheus metrics**:
  - `admin_api_requests_total` (Counter, labels: method, endpoint, status)
  - `admin_api_duration_seconds` (Histogram, labels: method, endpoint)
  - `admin_auth_attempts_total` (Counter, labels: status)
  - `admin_active_sessions` (Gauge)

- ✅ **Structured JSON logging** (Pino):
  - Log level: DEBUG (development), INFO (production)
  - Fields: timestamp, service_name, request_id, message
  - PII handling: Mask email addresses

- ✅ **Distributed tracing** (OpenTelemetry):
  - 100% sampling
  - Spans: http.request, grpc.call, postgres.query
  - Trace ID for each request

- ✅ **Health endpoints**:
  - GET /health → { status: "healthy", uptime_seconds: 86400 }
  - GET /ready → { status: "ready", dependencies: {...} }
  - GET /metrics → Prometheus text format

### 5.4 Performance

- ✅ **Authentication:** <200ms
- ✅ **Dashboard data:** <1s (aggregates from multiple services)
- ✅ **Invoice search:** <500ms (PostgreSQL query)
- ✅ **Error list:** <300ms

### 5.5 Testing

- ✅ **85%+ coverage** (jest.config.js threshold)
- ✅ **Unit tests:** 70% of suite
- ✅ **Integration tests:** 25% of suite
- ✅ **E2E tests:** 5% of suite (critical paths)
- ✅ **All tests pass** before committing

---

## 6. COMMON PITFALLS (Avoid These)

❌ **DON'T:**
- Use `.clear()` on Prometheus registry (use `.resetMetrics()` in tests)
- Store JWT secret in code (use environment variable)
- Skip rate limiting (DDoS risk)
- Disable CORS (security risk)
- Log unmasked email addresses (PII violation)
- Use weak password hashing (bcrypt cost < 12)
- Skip RBAC checks (authorization bypass)

✅ **DO:**
- Follow patterns from xsd-validator and schematron-validator
- Implement TODO-008 observability compliance
- Test authentication flow thoroughly (login, logout, refresh, expired tokens)
- Test RBAC (admin, operator, viewer roles)
- Document all operational scenarios in RUNBOOK
- Create comprehensive completion report

---

## 7. ACCEPTANCE CRITERIA

**Your service is COMPLETE when:**

### 7.1 Functional Requirements
- [ ] JWT authentication (login/logout/refresh)
- [ ] RBAC authorization (admin/operator/viewer roles)
- [ ] User management API (CRUD users)
- [ ] Manual error review API (resolve/resubmit)
- [ ] Invoice search API (with filters)
- [ ] Health dashboard API (aggregate from health-monitor)
- [ ] Reporting API (monthly summaries)
- [ ] Certificate management API (list/upload)

### 7.2 Non-Functional Requirements
- [ ] Authentication: <200ms (benchmarked)
- [ ] Dashboard: <1s (load tested)
- [ ] Test coverage: 85%+ (jest report confirms)
- [ ] Observability: 4+ Prometheus metrics implemented
- [ ] Security: Rate limiting, CORS, Helmet, bcrypt applied
- [ ] Documentation: README.md + RUNBOOK.md complete

### 7.3 Deliverables
- [ ] All code in `src/` directory
- [ ] All tests in `tests/` directory (passing)
- [ ] `.env.example` (all variables documented)
- [ ] `Dockerfile` (multi-stage, secure)
- [ ] `admin-portal-api.service` (systemd unit with hardening)
- [ ] `RUNBOOK.md` (comprehensive operations guide)
- [ ] Completion report in `/docs/reports/`
- [ ] Committed and pushed to `claude/admin-portal-api-{session-id}` branch

---

## 8. HELP & REFERENCES

**If you get stuck:**

1. **Reference implementations:**
   - `/services/xsd-validator/` - First service (validation pattern)
   - `/services/schematron-validator/` - Second service (observability pattern)

2. **Specifications:**
   - `README.md` (this directory) - Your primary spec
   - `/services/audit-logger/README.md` - gRPC audit trail
   - `/services/health-monitor/README.md` - Health dashboard
   - `/services/dead-letter-handler/README.md` - Manual review

3. **Standards:**
   - `/CLAUDE.md` - System architecture
   - `/docs/TODO-008-cross-cutting-concerns.md` - Observability requirements

4. **Dependencies:**
   - Depends on multiple services (HTTP/gRPC queries)
   - Can implement in parallel with other services (queries are read-only)

---

## 9. SUCCESS METRICS

**You've succeeded when:**

✅ All tests pass (`npm test`)
✅ Coverage ≥85% (`npm run test:coverage`)
✅ Service starts without errors (`npm run dev`)
✅ Health endpoints respond correctly
✅ JWT authentication works (login/logout/refresh)
✅ RBAC authorization works (all 3 roles)
✅ User management works (CRUD users)
✅ Manual review works (list/resolve/resubmit errors)
✅ Dashboard aggregation works (health-monitor data)
✅ Invoice search works (audit-logger queries)
✅ Certificate management works (cert-lifecycle-manager queries)
✅ RUNBOOK.md covers all operational scenarios
✅ Completion report written
✅ Code pushed to branch

---

## 10. TIMELINE CHECKPOINT

**Day 1 End:** Core implementation complete (auth, users, observability)
**Day 2 End:** Error review + invoice search complete
**Day 3 End:** Health dashboard + reports + certificates complete
**Day 4 End:** All tests written and passing (85%+ coverage)
**Day 5 End:** Documentation complete, code committed & pushed

**If you're behind schedule:**
- Prioritize authentication + user management (most critical)
- Manual review can be simplified (fewer endpoints)
- Ensure observability compliance (non-negotiable)
- Ask for help if blocked >2 hours

---

**Status:** 🔴 Ready for Implementation
**Last Updated:** 2025-11-11
**Assigned To:** [Your AI Instance]
**Session ID:** [Your Session ID]

---

## FINAL REMINDER

**Read the specification (`README.md`) thoroughly before writing code.**

This CLAUDE.md provides workflow and context. The README.md provides technical details. Together, they contain everything you need to implement this service to production standards.

**Good luck!**
