# Notification Service - Specification

**Service Name:** `notification-service`
**Layer:** Infrastructure (Layer 9)
**Complexity:** Low (~900 LOC)
**Status:** 🔴 Specification Only (Ready for Implementation)

---

## 1. Purpose and Single Responsibility

**Send email/SMS alerts for errors, confirmations, reminders, and system events.**

This service is the **single notification channel** for the entire platform. It receives notification requests from other services and dispatches them via:
- Email (SMTP) - User confirmations, error reports, monthly summaries
- SMS (Tw

ilio/similar) - Critical alerts, 2FA codes
- Webhook (HTTP POST) - External system integrations

---

## 2. Integration Architecture

### 2.1 Dependencies

**Consumes:**
- RabbitMQ queue: `notifications.send` (notification requests from all services)
- HTTP POST `/notifications` (REST API for synchronous notifications)

**Produces:**
- SMTP emails (via external mail server)
- SMS messages (via Twilio/similar API)
- Webhook POST requests (to external URLs)

### 2.2 Message Contract

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

## 3. Notification Templates

**Email Templates:**
- `invoice_submitted.html` - Invoice successfully submitted to FINA
- `invoice_failed.html` - Invoice validation/submission failed
- `monthly_summary.html` - Monthly invoice processing summary
- `system_alert.html` - Critical system errors

**SMS Templates:**
- `critical_error.txt` - "[eRacun] CRITICAL: Service {service_name} down"
- `2fa_code.txt` - "Your eRacun verification code: {code}"

**Template Engine:** Handlebars or similar

---

## 4. Technology Stack

**Core:**
- Node.js 20+ / TypeScript 5.3+
- `nodemailer` - SMTP email sending
- `twilio` - SMS sending (or alternative provider)
- `axios` - Webhook HTTP client
- `amqplib` - RabbitMQ consumer
- `express` - HTTP API

**Observability:**
- `prom-client`, `pino`, `opentelemetry`

---

## 5. Performance Requirements

**Throughput:**
- Emails: 100/minute sustained, 500/minute burst
- SMS: 10/minute (rate limit to avoid carrier throttling)
- Webhooks: 100/second

**Latency:**
- Critical notifications: <10 seconds from request to send
- Normal notifications: <5 minutes
- Low priority: Batched daily

**Reliability:**
- Retry failed sends (exponential backoff, max 3 retries)
- Store notifications in PostgreSQL for audit trail
- Dead letter queue for permanently failed notifications

---

## 6. Implementation Guidance

### 6.1 File Structure

```
services/notification-service/
├── src/
│   ├── index.ts            # Main (RabbitMQ + HTTP API)
│   ├── email-sender.ts     # SMTP integration
│   ├── sms-sender.ts       # Twilio integration
│   ├── webhook-sender.ts   # HTTP POST client
│   ├── templates/          # Notification templates
│   └── observability.ts
├── tests/
└── ...
```

### 6.2 Core Logic

```typescript
async function sendNotification(notification: SendNotificationCommand) {
  // Store in database (audit trail)
  await saveNotification(notification);

  switch (notification.type) {
    case NotificationType.EMAIL:
      await sendEmail(notification);
      break;
    case NotificationType.SMS:
      await sendSMS(notification);
      break;
    case NotificationType.WEBHOOK:
      await sendWebhook(notification);
      break;
  }

  // Metrics
  notificationsSent.inc({ type: notification.type, priority: notification.priority });
}
```

---

## 7. Observability (TODO-008)

**Metrics:**
```typescript
const notificationsSent = new Counter({
  name: 'notifications_sent_total',
  labelNames: ['type', 'priority', 'status']  // status: success/failed
});

const notificationSendDuration = new Histogram({
  name: 'notification_send_duration_seconds',
  labelNames: ['type']
});

const notificationQueueDepth = new Gauge({
  name: 'notification_queue_depth',
  help: 'Pending notifications in queue'
});
```

---

## 8. Configuration

```bash
# .env.example
SERVICE_NAME=notification-service
HTTP_PORT=8085

# SMTP Configuration
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=noreply@eracun.hr
SMTP_PASSWORD=<encrypted>
SMTP_FROM=noreply@eracun.hr

# SMS Configuration (Twilio)
TWILIO_ACCOUNT_SID=ACxxxxxx
TWILIO_AUTH_TOKEN=<encrypted>
TWILIO_FROM_NUMBER=+385xxxxxxxx

# RabbitMQ
RABBITMQ_URL=amqp://localhost:5672
NOTIFICATION_QUEUE=notifications.send

# Rate Limits
EMAIL_RATE_LIMIT_PER_MINUTE=100
SMS_RATE_LIMIT_PER_MINUTE=10
```

---

## 9. Acceptance Criteria

- [ ] Send emails via SMTP (with templates)
- [ ] Send SMS via Twilio (with rate limiting)
- [ ] Send webhooks via HTTP POST
- [ ] RabbitMQ consumer + HTTP API
- [ ] Priority-based sending (critical → immediate)
- [ ] Retry logic (3 attempts with backoff)
- [ ] Audit trail in PostgreSQL
- [ ] Test coverage 85%+

---

**Status:** 🔴 Ready for Implementation
**Estimate:** 2-3 days | **Complexity:** Low (~900 LOC)
**Dependencies:** None

---

**Last Updated:** 2025-11-11
