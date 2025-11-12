# Service: notification-service

## Purpose
Multi-channel notification delivery (email, SMS) for critical system events.
Alerts users about certificate expiration, validation failures, and system issues.

## Status
**Coverage:** 97.81% statements, 100% functions/lines, 79% branches
**Tests:** 45 tests passing
**Implementation:** ✅ Complete

## Dependencies
- Twilio: SMS delivery (account SID, auth token)
- Nodemailer: Email delivery (SMTP configuration)
- RabbitMQ: Notification requests queue
- Redis: Rate limiting and deduplication

## Commands
```bash
npm run dev              # Start development server
npm test                 # Run all tests (45 tests)
npm run build            # Build service
npm run lint             # Run linter
```

## Message Handlers
- `SendEmailNotification` - Deliver email with templates
- `SendSMSNotification` - Deliver SMS via Twilio
- `SendBatchNotifications` - Bulk delivery with throttling

## Service Constraints
- Email rate limit: 100/hour per recipient
- SMS rate limit: 10/hour per phone number
- Template rendering: Handlebars with XSS protection
- Retry policy: 3 attempts with exponential backoff

## Key Features
- Multi-channel delivery (email + SMS)
- Template-based notifications (Handlebars)
- Rate limiting and deduplication
- Delivery status tracking
- Failed notification dead letter queue

## Related Services
- Consumes from: `cert-lifecycle-manager` (expiration alerts)
- Consumes from: `health-monitor` (system alerts)
- Consumes from: `audit-logger` (security alerts)

## Configuration
- Twilio: `TWILIO_ACCOUNT_SID`, `TWILIO_AUTH_TOKEN`, `TWILIO_PHONE_NUMBER`
- SMTP: `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASS`
- Templates: `templates/` directory (Handlebars .hbs files)

---

See `README.md` for complete implementation details.
See `@docs/OPERATIONS.md` for alert configuration.
