# Admin Portal API Service - Specification

**Service Name:** `admin-portal-api`
**Layer:** Management (Layer 10)
**Complexity:** Medium (~2,000 LOC)
**Status:** 🔴 Specification Only (Ready for Implementation)

---

## 1. Purpose and Single Responsibility

**Provide REST API for admin UI (user management, manual review, reporting, system configuration).**

This service is the **backend for the administrative web portal**. It aggregates data from all services and provides:
- User management (CRUD users, roles, permissions)
- Manual error review (DLQ messages requiring human intervention)
- Invoice search and retrieval
- System health dashboard data
- Configuration management
- Reporting (monthly summaries, error statistics, submission rates)

---

## 2. Integration Architecture

### 2.1 Dependencies

**Queries (Read-Only):**
- `audit-logger` (gRPC): Query audit trails
- `health-monitor` (HTTP): System health status
- `dead-letter-handler` (PostgreSQL): Manual review queue
- `archive-service` (HTTP): Retrieve archived invoices
- `cert-lifecycle-manager` (HTTP): Certificate inventory
- `kpd-registry-sync` (gRPC): KPD code lookups

**Commands (Write):**
- `dead-letter-handler` (HTTP): Resolve/resubmit errors
- `cert-lifecycle-manager` (HTTP): Upload new certificates
- `notification-service` (RabbitMQ): Send admin notifications

**No Direct Database Access to Service Databases** (queries via service APIs only)

**Own PostgreSQL Database:**
- `admin_portal` database (users, roles, permissions, sessions)

### 2.2 Authentication & Authorization

**Authentication:**
- JWT tokens (issued after login)
- Session management (Redis or PostgreSQL)
- 2FA support (optional, via TOTP)

**Authorization:**
- Role-Based Access Control (RBAC)
- Roles: `admin`, `operator`, `viewer`
- Permissions:
  - `admin`: Full access (user management, configuration, certificate upload)
  - `operator`: Manual review, invoice search, reporting
  - `viewer`: Read-only (dashboard, reports)

**User Schema:**
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
```

---

## 3. REST API Specification

### 3.1 Authentication Endpoints

```
POST   /api/v1/auth/login            # Login (email/password) → JWT token
POST   /api/v1/auth/logout           # Logout (invalidate token)
POST   /api/v1/auth/refresh          # Refresh JWT token
GET    /api/v1/auth/me               # Get current user info
```

### 3.2 User Management (Admin Only)

```
GET    /api/v1/users                 # List all users
POST   /api/v1/users                 # Create new user
GET    /api/v1/users/:id             # Get user details
PATCH  /api/v1/users/:id             # Update user (role, active status)
DELETE /api/v1/users/:id             # Deactivate user
```

### 3.3 Manual Error Review (Operator+)

```
GET    /api/v1/errors                # List errors in manual review
GET    /api/v1/errors/:id            # Get error details
POST   /api/v1/errors/:id/resolve    # Mark as resolved
POST   /api/v1/errors/:id/resubmit   # Resubmit to original queue
POST   /api/v1/errors/bulk-resolve   # Bulk resolve multiple errors
```

### 3.4 Invoice Management (Operator+)

```
GET    /api/v1/invoices              # Search invoices (filters: date, OIB, status)
GET    /api/v1/invoices/:id          # Get invoice details
GET    /api/v1/invoices/:id/audit    # Get audit trail (from audit-logger)
GET    /api/v1/invoices/:id/xml      # Download original XML
POST   /api/v1/invoices/:id/reprocess # Reprocess failed invoice
```

### 3.5 System Health (Viewer+)

```
GET    /api/v1/health/dashboard      # System-wide health (from health-monitor)
GET    /api/v1/health/services       # All services status
GET    /api/v1/health/external       # External dependencies status
GET    /api/v1/health/circuit-breakers # Circuit breaker states
```

### 3.6 Reporting (Viewer+)

```
GET    /api/v1/reports/monthly       # Monthly invoice summary
GET    /api/v1/reports/errors        # Error statistics (by service, type)
GET    /api/v1/reports/submissions   # Submission rates (B2C/B2B/B2G)
GET    /api/v1/reports/performance   # Service performance metrics
```

### 3.7 Certificate Management (Admin Only)

```
GET    /api/v1/certificates          # List certificates (from cert-lifecycle-manager)
POST   /api/v1/certificates/upload   # Upload new certificate
GET    /api/v1/certificates/expiring # Certificates expiring soon
```

### 3.8 Configuration Management (Admin Only)

```
GET    /api/v1/config                # Get system configuration
PATCH  /api/v1/config                # Update configuration
POST   /api/v1/config/reload         # Reload configuration (trigger config reload in services)
```

---

## 4. Technology Stack

**Core:**
- Node.js 20+ / TypeScript 5.3+
- `express` - HTTP server
- `jsonwebtoken` - JWT authentication
- `bcrypt` - Password hashing
- `pg` - PostgreSQL client (users database)
- `axios` - HTTP client (query other services)
- `@grpc/grpc-js` - gRPC client (audit-logger, kpd-registry-sync)

**Observability:**
- `prom-client`, `pino`, `opentelemetry`

**Security:**
- `helmet` - Security headers
- `express-rate-limit` - Rate limiting
- `cors` - CORS configuration

---

## 5. Performance Requirements

**Throughput:**
- 100 requests/second (dashboard queries)
- 10 requests/second (write operations)

**Latency:**
- Authentication: <200ms
- Dashboard data: <1s (aggregates from multiple services)
- Invoice search: <500ms (PostgreSQL query)
- Error list: <300ms

**Reliability:**
- Availability: 99.9% (admin portal must be accessible)

---

## 6. Implementation Guidance

### 6.1 File Structure

```
services/admin-portal-api/
├── src/
│   ├── index.ts              # Main server
│   ├── auth/
│   │   ├── middleware.ts     # JWT authentication middleware
│   │   ├── rbac.ts           # Role-based access control
│   │   └── routes.ts         # Auth endpoints
│   ├── users/
│   │   ├── controller.ts     # User management logic
│   │   ├── repository.ts     # PostgreSQL queries
│   │   └── routes.ts         # User endpoints
│   ├── errors/
│   │   ├── controller.ts     # Manual review logic
│   │   └── routes.ts
│   ├── invoices/
│   │   ├── controller.ts     # Invoice search/retrieval
│   │   └── routes.ts
│   ├── health/
│   │   ├── controller.ts     # Health dashboard aggregation
│   │   └── routes.ts
│   ├── reports/
│   │   ├── controller.ts     # Report generation
│   │   └── routes.ts
│   ├── certificates/
│   │   ├── controller.ts     # Certificate management
│   │   └── routes.ts
│   ├── clients/              # HTTP/gRPC clients for other services
│   │   ├── audit-logger.ts
│   │   ├── health-monitor.ts
│   │   └── dead-letter-handler.ts
│   └── observability.ts
├── tests/
└── ...
```

### 6.2 Authentication Middleware

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

export function requireRole(...roles: string[]) {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({ error: 'Insufficient permissions' });
    }
    next();
  };
}

// Usage:
app.get('/api/v1/users', authenticateJWT, requireRole('admin'), listUsers);
```

### 6.3 Dashboard Data Aggregation

```typescript
async function getDashboardData() {
  const [
    systemHealth,
    errorStats,
    invoiceStats,
    certificates
  ] = await Promise.all([
    axios.get('http://health-monitor:8084/health/dashboard'),
    axios.get('http://dead-letter-handler:8081/api/v1/errors/stats'),
    queryInvoiceStats(),
    axios.get('http://cert-lifecycle-manager:8087/api/v1/certificates/expiring')
  ]);

  return {
    system_health: systemHealth.data,
    error_stats: errorStats.data,
    invoice_stats: invoiceStats,
    expiring_certificates: certificates.data
  };
}
```

---

## 7. Observability (TODO-008)

**Metrics:**
```typescript
const apiRequests = new Counter({
  name: 'admin_api_requests_total',
  labelNames: ['method', 'endpoint', 'status']
});

const apiDuration = new Histogram({
  name: 'admin_api_duration_seconds',
  labelNames: ['method', 'endpoint'],
  buckets: [0.01, 0.05, 0.1, 0.5, 1, 5]
});

const authAttempts = new Counter({
  name: 'admin_auth_attempts_total',
  labelNames: ['status']  // success, failed
});

const activeSessions = new Gauge({
  name: 'admin_active_sessions',
  help: 'Number of active user sessions'
});
```

---

## 8. Security Considerations

**Password Security:**
- bcrypt hashing (cost factor: 12)
- Password requirements: min 12 characters, uppercase, lowercase, digit, symbol

**Rate Limiting:**
- Login endpoint: 5 attempts per 15 minutes per IP
- API endpoints: 100 requests per minute per user

**CORS:**
- Whitelist admin portal frontend domain only
- Credentials: true (allow cookies)

**Security Headers (Helmet):**
- Content-Security-Policy
- X-Frame-Options: DENY
- X-Content-Type-Options: nosniff

---

## 9. Configuration

```bash
# .env.example
SERVICE_NAME=admin-portal-api
HTTP_PORT=8089

# JWT Configuration
JWT_SECRET=<random 256-bit key>
JWT_EXPIRY=1h
JWT_REFRESH_EXPIRY=7d

# PostgreSQL (Admin Portal Database)
DATABASE_URL=postgresql://admin_api:password@localhost:5432/admin_portal

# Service URLs
HEALTH_MONITOR_URL=http://health-monitor:8084
DEAD_LETTER_HANDLER_URL=http://dead-letter-handler:8081
AUDIT_LOGGER_GRPC=audit-logger:50051
CERT_MANAGER_URL=http://cert-lifecycle-manager:8087

# Security
BCRYPT_ROUNDS=12
SESSION_TIMEOUT_HOURS=24
RATE_LIMIT_WINDOW_MS=900000  # 15 minutes
RATE_LIMIT_MAX=5

# CORS
CORS_ORIGIN=https://admin.eracun.hr

# Observability
LOG_LEVEL=info
PROMETHEUS_PORT=9094
```

---

## 10. Acceptance Criteria

- [ ] JWT authentication (login/logout/refresh)
- [ ] RBAC authorization (admin/operator/viewer roles)
- [ ] User management API (CRUD users)
- [ ] Manual error review API (resolve/resubmit)
- [ ] Invoice search API (with filters)
- [ ] Health dashboard API (aggregate from health-monitor)
- [ ] Reporting API (monthly summaries)
- [ ] Certificate management API (list/upload)
- [ ] Rate limiting (login: 5/15min, API: 100/min)
- [ ] Security headers (Helmet)
- [ ] Test coverage 85%+
- [ ] 4+ Prometheus metrics

---

**Status:** 🔴 Ready for Implementation
**Estimate:** 4-5 days | **Complexity:** Medium (~2,000 LOC)
**Dependencies:** None

---

**Last Updated:** 2025-11-11
