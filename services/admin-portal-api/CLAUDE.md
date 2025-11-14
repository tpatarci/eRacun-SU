# Service: admin-portal-api

## Purpose
RESTful API for eRacun administration portal.
Provides user management, certificate upload, system monitoring, and configuration.

## Status
**Coverage:** 60.41% statements (REST API layer)
**Tests:** 4 tests (requires expansion)
**Implementation:** 🟡 Partial (core features complete)

## Dependencies
- PostgreSQL: User accounts, sessions, audit logs
- Redis: Session storage and caching
- RabbitMQ: Admin operations publishing
- All eRacun services: Service status monitoring

## Commands
```bash
npm run dev              # Start development server
npm test                 # Run all tests
npm run build            # Build service
npm run migrate          # Run database migrations
```

## API Endpoints
**Authentication:**
- `POST /api/v1/auth/login` - User login (JWT tokens)
- `POST /api/v1/auth/logout` - User logout
- `POST /api/v1/auth/refresh` - Refresh access token

**Certificates:**
- `POST /api/v1/certificates` - Upload .p12 certificate
- `GET /api/v1/certificates` - List certificates
- `DELETE /api/v1/certificates/:id` - Revoke certificate

**Monitoring:**
- `GET /api/v1/health` - System health dashboard
- `GET /api/v1/metrics` - Prometheus metrics proxy
- `GET /api/v1/services` - Service status overview

**Users:**
- `POST /api/v1/users` - Create user (admin only)
- `GET /api/v1/users` - List users
- `PUT /api/v1/users/:id` - Update user
- `DELETE /api/v1/users/:id` - Delete user

## Service Constraints
- Rate limit: 100 req/min per user
- Session timeout: 1 hour (access token), 30 days (refresh)
- Max file upload: 1MB (certificates)
- RBAC: Admin, Operator, Viewer roles

## Key Features
- JWT-based authentication
- Role-based access control (RBAC)
- Certificate management UI backend
- System monitoring dashboard API
- User account management

## Related Services
- Publishes to: `cert-lifecycle-manager` (certificate uploads)
- Consumes from: `health-monitor` (service status)
- Consumes from: `audit-logger` (audit trail)

---

See `README.md` for complete implementation details.
See `@docs/SECURITY.md` for authentication requirements.
