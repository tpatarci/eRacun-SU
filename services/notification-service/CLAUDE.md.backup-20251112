# CLAUDE.md - Notification Service

**Service:** `notification-service`
**Layer:** Infrastructure (Layer 9)
**Implementation Status:** 🔴 Not Started
**Your Mission:** Implement this service from specification to production-ready

---

## 1. YOUR MISSION

You are implementing the **notification-service** for the eRacun e-invoice processing platform. This service is the **single notification channel** for the entire system, handling all email, SMS, and webhook alerts.

**What you're building:**
- Email sender (SMTP integration with templates)
- SMS sender (Twilio/similar integration with rate limiting)
- Webhook dispatcher (HTTP POST to external URLs)
- RabbitMQ consumer + HTTP REST API (synchronous notifications)

**Estimated effort:** 2-3 days
**Complexity:** Low (~900 LOC)

---

## 2. REQUIRED READING (Read in Order)

**Before writing any code, read these documents:**

1. **`README.md`** (in this directory) - Complete service specification
2. **`/CLAUDE.md`** (repository root) - System architecture and standards
3. **`/docs/TODO-008-cross-cutting-concerns.md`** - Observability requirements (MANDATORY)
4. **`/services/xsd-validator/`** - Reference implementation pattern
5. **`/services/schematron-validator/`** - Reference observability module

**Time investment:** 25-35 minutes reading
**Why mandatory:** Prevents rework, ensures compliance, establishes patterns

---

## 3. ARCHITECTURAL CONTEXT

### 3.1 Where This Service Fits

```
┌─────────────────────────────────────────────────────────────┐
│ ALL SERVICES                                                │
│ (dead-letter-handler, health-monitor, cert-lifecycle-      │
│  manager, admin-portal-api, ...)                           │
└────────────────────┬────────────────────────────────────────┘
                     │
                     │ Notification requests
                     ▼
            ┌────────────────────┐
            │  RabbitMQ Queue    │
            │  'notifications.   │
            │   send'            │
            └────────┬───────────┘
                     │
            OR       │ Consume
                     ▼
            ┌────────────────────┐
            │  HTTP REST API     │
            │  POST /            │
            │  notifications     │
            └────────┬───────────┘
                     │
                     │ Both lead to
                     ▼
            ┌────────────────────┐
            │  THIS SERVICE      │
            │  notification-     │
            │  service           │
            └────────┬───────────┘
                     │
        ┌────────────┼────────────┐
        │            │            │
        ▼            ▼            ▼
   Email (SMTP)  SMS (Twilio) Webhook (HTTP)
```

### 3.2 Critical Dependencies

**Upstream (Consumes From):**
- RabbitMQ queue: `notifications.send` (async notifications)
- HTTP POST `/notifications` (sync notifications)

**Downstream (Produces To):**
- SMTP server (email delivery)
- Twilio API (SMS delivery)
- External webhook URLs (HTTP POST)

**PostgreSQL Table:**
- `notification_log` (audit trail of all sent notifications)

### 3.3 Message Contract

**Notification Request Schema:**

```protobuf
message SendNotificationCommand {
  string notification_id = 1;      // UUID
  NotificationType type = 2;        // email, sms, webhook
  NotificationPriority priority = 3; // low, normal, high, critical
  repeated string recipients = 4;   // Email addresses or phone numbers
  string subject = 5;               // Email subject or SMS title
  string body = 6;                  // Message content (supports templates)
  map<string, string> template_vars = 7; // Template variable substitution
  string webhook_url = 8;           // For webhook notifications
}

enum NotificationType {
  EMAIL = 0;
  SMS = 1;
  WEBHOOK = 2;
}

enum NotificationPriority {
  LOW = 0;          // Batch send (daily digest)
  NORMAL = 1;       // Send within 5 minutes
  HIGH = 2;         // Send within 1 minute
  CRITICAL = 3;     // Send immediately (system outage, security breach)
}
```

---

## 4. IMPLEMENTATION WORKFLOW

**Follow this sequence strictly:**

### Phase 1: Setup (Day 1, Morning)

1. **Create package.json**
   ```bash
   npm init -y
   npm install --save nodemailer twilio axios amqplib pg express handlebars prom-client pino opentelemetry
   npm install --save-dev typescript @types/node @types/nodemailer @types/express jest @types/jest ts-jest
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
   ├── index.ts              # Main entry (RabbitMQ + HTTP API)
   ├── email-sender.ts       # SMTP integration
   ├── sms-sender.ts         # Twilio integration
   ├── webhook-sender.ts     # HTTP POST client
   ├── template-engine.ts    # Handlebars template rendering
   ├── rate-limiter.ts       # SMS rate limiting
   ├── repository.ts         # PostgreSQL (notification log)
   └── observability.ts      # Metrics, logs, traces (TODO-008)
   templates/
   ├── email/
   │   ├── invoice_submitted.html
   │   ├── invoice_failed.html
   │   ├── monthly_summary.html
   │   └── system_alert.html
   └── sms/
       ├── critical_error.txt
       └── 2fa_code.txt
   tests/
   ├── setup.ts
   ├── unit/
   │   ├── email-sender.test.ts
   │   ├── sms-sender.test.ts
   │   ├── template-engine.test.ts
   │   └── observability.test.ts
   └── integration/
       ├── rabbitmq-consumer.test.ts
       └── api.test.ts
   ```

### Phase 2: Core Implementation (Day 1 Afternoon - Day 2)

1. **Implement observability.ts FIRST** (TODO-008 compliance)
   - Copy pattern from `/services/xsd-validator/src/observability.ts`
   - Define 3+ Prometheus metrics (see README.md Section 7)
   - Structured logging (Pino)
   - Distributed tracing (OpenTelemetry)
   - PII masking (email addresses, phone numbers in logs)

2. **Implement template-engine.ts** (Handlebars templates)
   - `renderTemplate(templateName, variables): string`
   - Load templates from `templates/` directory
   - Cache compiled templates (performance)
   - Support both HTML (email) and plain text (SMS)

3. **Implement email-sender.ts** (SMTP integration)
   - `sendEmail(recipients, subject, body, priority): Promise<void>`
   - Use nodemailer (SMTP transport)
   - Configuration: SMTP host, port, credentials (from env vars)
   - Retry logic: 3 attempts with exponential backoff
   - Track sent emails in PostgreSQL (audit trail)

4. **Implement sms-sender.ts** (Twilio integration)
   - `sendSMS(recipients, message, priority): Promise<void>`
   - Use Twilio client
   - Rate limiting: 10 SMS/minute (prevent carrier throttling)
   - Priority queue: Critical messages bypass rate limit
   - Track sent SMS in PostgreSQL

5. **Implement webhook-sender.ts** (HTTP POST client)
   - `sendWebhook(url, payload): Promise<void>`
   - HTTP POST with 10-second timeout
   - Retry logic: 3 attempts
   - Track sent webhooks in PostgreSQL

6. **Implement rate-limiter.ts** (SMS rate limiting)
   - Token bucket algorithm (10 tokens/minute)
   - Priority bypass: CRITICAL notifications skip rate limit
   - Queue low-priority SMS for batch sending

7. **Implement repository.ts** (PostgreSQL notification log)
   - Connection pool (min: 10, max: 50)
   - `saveNotification(notification, status, sent_at)`
   - Schema:
     ```sql
     CREATE TABLE notification_log (
       id BIGSERIAL PRIMARY KEY,
       notification_id UUID NOT NULL,
       type VARCHAR(50) NOT NULL,
       priority VARCHAR(50) NOT NULL,
       recipients TEXT[] NOT NULL,
       subject TEXT,
       body TEXT,
       status VARCHAR(50) DEFAULT 'pending',  -- pending, sent, failed
       sent_at TIMESTAMP,
       error_message TEXT,
       created_at TIMESTAMP DEFAULT NOW()
     );
     ```

8. **Implement index.ts** (Main entry point)
   - Start RabbitMQ consumer (`notifications.send` queue)
   - Start HTTP API server (port 8085)
   - Route to email/SMS/webhook sender based on type
   - Priority-based dispatch (critical → immediate, normal → 5min, low → batch)
   - Start Prometheus metrics endpoint (port 9093)
   - Health check endpoint (GET /health, GET /ready)
   - Graceful shutdown (SIGTERM, SIGINT)

### Phase 3: Testing (Day 2-3)

1. **Create test fixtures**
   - `tests/fixtures/notification-requests.json` (10 sample notifications)
   - Mock SMTP server (nodemailer-mock)
   - Mock Twilio client
   - Mock HTTP server (for webhooks)

2. **Write unit tests** (70% of suite)
   - `email-sender.test.ts`: SMTP integration, retry logic
   - `sms-sender.test.ts`: Twilio integration, rate limiting
   - `template-engine.test.ts`: Template rendering
   - `observability.test.ts`: Metrics, logging (PII masking)
   - Target: 90%+ coverage for critical paths

3. **Write integration tests** (25% of suite)
   - `rabbitmq-consumer.test.ts`: End-to-end (RabbitMQ → send)
   - `api.test.ts`: HTTP POST endpoint

4. **Run tests**
   ```bash
   npm test -- --coverage
   ```
   - **MUST achieve 85%+ coverage** (enforced in jest.config.js)

### Phase 4: Documentation (Day 3)

1. **Create RUNBOOK.md** (operations guide)
   - Copy structure from `/services/schematron-validator/RUNBOOK.md`
   - Sections: Deployment, Monitoring, Common Issues, Troubleshooting, Disaster Recovery
   - Scenarios:
     - SMTP server unavailable
     - Twilio rate limit exceeded
     - Webhook endpoint down
     - RabbitMQ queue backlog
   - Minimum 8 operational scenarios documented

2. **Create email templates** (`templates/email/`)
   - `invoice_submitted.html` (success confirmation)
   - `invoice_failed.html` (error notification)
   - `monthly_summary.html` (monthly report)
   - `system_alert.html` (critical alerts)

3. **Create SMS templates** (`templates/sms/`)
   - `critical_error.txt` (system outage)
   - `2fa_code.txt` (verification codes)

4. **Create .env.example**
   - All environment variables documented
   - Include: SMTP_HOST, SMTP_USER, SMTP_PASSWORD, TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN

5. **Create Dockerfile**
   - Multi-stage build (build → production)
   - Security: Run as non-root user, minimal base image

6. **Create systemd unit file** (`notification-service.service`)
   - Security hardening: ProtectSystem=strict, NoNewPrivileges=true
   - Restart policy: always, RestartSec=10
   - Copy from `/services/xsd-validator/*.service`

7. **Create completion report**
   - File: `/docs/reports/{date}-notification-service-completion.md`
   - Template: `/docs/reports/2025-11-11-schematron-validator-completion.md`
   - Sections: Executive Summary, Deliverables, Git Status, Traceability, Next Steps

### Phase 5: Commit & Push (Day 3)

1. **Commit all work**
   ```bash
   git add services/notification-service/
   git commit -m "feat(notification-service): implement email/SMS/webhook notification service"
   ```

2. **Push to branch**
   ```bash
   git push -u origin claude/notification-service-{your-session-id}
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
- ✅ **SMTP credentials encrypted** (SOPS + age in production)
- ✅ **Twilio credentials encrypted** (SOPS + age)
- ✅ **PII masking in logs** (email addresses, phone numbers)
- ✅ **systemd security hardening** (ProtectSystem=strict, etc.)

### 5.3 Observability (TODO-008 Compliance)

**MANDATORY - Your service MUST include:**

- ✅ **3+ Prometheus metrics**:
  - `notifications_sent_total` (Counter, labels: type, priority, status)
  - `notification_send_duration_seconds` (Histogram, labels: type)
  - `notification_queue_depth` (Gauge)

- ✅ **Structured JSON logging** (Pino):
  - Log level: DEBUG (development), INFO (production)
  - Fields: timestamp, service_name, request_id, message
  - PII handling: Mask email addresses, phone numbers

- ✅ **Distributed tracing** (OpenTelemetry):
  - 100% sampling
  - Spans: rabbitmq.consume, send_email, send_sms, send_webhook
  - Trace ID propagated from RabbitMQ message

- ✅ **Health endpoints**:
  - GET /health → { status: "healthy", uptime_seconds: 86400 }
  - GET /ready → { status: "ready", dependencies: {...} }
  - GET /metrics → Prometheus text format

### 5.4 Performance

- ✅ **Throughput:** 100 emails/minute, 10 SMS/minute, 100 webhooks/second
- ✅ **Latency:** <10 seconds for CRITICAL notifications
- ✅ **Reliability:** Retry failed sends (max 3 attempts)

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
- Skip rate limiting on SMS (carrier throttling risk)
- Log unmasked email addresses or phone numbers (PII violation)
- Hardcode SMTP/Twilio credentials
- Ignore notification failures (must retry and log)
- Send emails without templates (poor UX)

✅ **DO:**
- Follow patterns from xsd-validator and schematron-validator
- Implement TODO-008 observability compliance
- Test template rendering thoroughly
- Test retry logic (SMTP failures, Twilio errors)
- Document all operational scenarios in RUNBOOK
- Create comprehensive completion report

---

## 7. ACCEPTANCE CRITERIA

**Your service is COMPLETE when:**

### 7.1 Functional Requirements
- [ ] Send emails via SMTP (with templates)
- [ ] Send SMS via Twilio (with rate limiting)
- [ ] Send webhooks via HTTP POST
- [ ] RabbitMQ consumer + HTTP API
- [ ] Priority-based sending (critical → immediate)
- [ ] Retry logic (3 attempts with backoff)
- [ ] Audit trail in PostgreSQL
- [ ] Template engine (Handlebars)

### 7.2 Non-Functional Requirements
- [ ] Throughput: 100 emails/min, 10 SMS/min, 100 webhooks/sec (load tested)
- [ ] Latency: <10s for critical notifications (benchmarked)
- [ ] Test coverage: 85%+ (jest report confirms)
- [ ] Observability: 3+ Prometheus metrics implemented
- [ ] Security: PII masking, systemd hardening applied
- [ ] Documentation: README.md + RUNBOOK.md complete

### 7.3 Deliverables
- [ ] All code in `src/` directory
- [ ] All tests in `tests/` directory (passing)
- [ ] Email templates in `templates/email/`
- [ ] SMS templates in `templates/sms/`
- [ ] `.env.example` (all variables documented)
- [ ] `Dockerfile` (multi-stage, secure)
- [ ] `notification-service.service` (systemd unit with hardening)
- [ ] `RUNBOOK.md` (comprehensive operations guide)
- [ ] Completion report in `/docs/reports/`
- [ ] Committed and pushed to `claude/notification-service-{session-id}` branch

---

## 8. HELP & REFERENCES

**If you get stuck:**

1. **Reference implementations:**
   - `/services/xsd-validator/` - First service (validation pattern)
   - `/services/schematron-validator/` - Second service (observability pattern)

2. **Specifications:**
   - `README.md` (this directory) - Your primary spec
   - `/docs/adr/003-system-decomposition-integration-architecture.md` - Service catalog

3. **Standards:**
   - `/CLAUDE.md` - System architecture
   - `/docs/TODO-008-cross-cutting-concerns.md` - Observability requirements

4. **Dependencies:**
   - This service has ZERO service dependencies (can implement immediately)
   - Only depends on RabbitMQ and PostgreSQL (infrastructure)

---

## 9. SUCCESS METRICS

**You've succeeded when:**

✅ All tests pass (`npm test`)
✅ Coverage ≥85% (`npm run test:coverage`)
✅ Service starts without errors (`npm run dev`)
✅ Health endpoints respond correctly
✅ RabbitMQ consumer processes messages
✅ Email sending works (SMTP)
✅ SMS sending works (Twilio, rate limited)
✅ Webhook sending works (HTTP POST)
✅ Template rendering works (all 4 email + 2 SMS templates)
✅ RUNBOOK.md covers all operational scenarios
✅ Completion report written
✅ Code pushed to branch

---

## 10. TIMELINE CHECKPOINT

**Day 1 End:** Core implementation complete (email, SMS, webhook senders, observability)
**Day 2 End:** RabbitMQ consumer + HTTP API + templates complete
**Day 3 End:** All tests written and passing (85%+ coverage), documentation complete, code committed & pushed

**If you're behind schedule:**
- Prioritize email sending (most critical notification type)
- SMS can be implemented after email
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
