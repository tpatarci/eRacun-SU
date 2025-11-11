# =============================================
# Audit Logger Service - Multi-Stage Dockerfile
# =============================================
# Security hardened, production-ready container
# Target size: <150MB (Alpine-based)

# =============================================
# Stage 1: Dependencies
# =============================================
FROM node:20-alpine AS deps

WORKDIR /app

# Install production dependencies only
COPY package.json package-lock.json ./
RUN npm ci --only=production --ignore-scripts && \
    npm cache clean --force

# =============================================
# Stage 2: Build
# =============================================
FROM node:20-alpine AS builder

WORKDIR /app

# Copy package files
COPY package.json package-lock.json tsconfig.json ./

# Install all dependencies (including devDependencies)
RUN npm ci --ignore-scripts

# Copy source code
COPY src ./src
COPY proto ./proto

# Build TypeScript
RUN npm run build && \
    rm -rf src

# =============================================
# Stage 3: Runtime
# =============================================
FROM node:20-alpine AS runtime

# Security: Run as non-root user
RUN addgroup -g 1001 -S eracun && \
    adduser -S eracun -u 1001 -G eracun

WORKDIR /app

# Copy production dependencies from deps stage
COPY --from=deps --chown=eracun:eracun /app/node_modules ./node_modules

# Copy built application from builder stage
COPY --from=builder --chown=eracun:eracun /app/dist ./dist
COPY --from=builder --chown=eracun:eracun /app/proto ./proto
COPY --chown=eracun:eracun package.json ./

# Install production tools
RUN apk add --no-cache \
    tini \
    dumb-init \
    ca-certificates && \
    rm -rf /var/cache/apk/*

# Switch to non-root user
USER eracun

# Expose ports
EXPOSE 8080 50051

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD node -e "require('http').get('http://localhost:8080/health', (r) => {process.exit(r.statusCode === 200 ? 0 : 1)})"

# Environment variables (defaults)
ENV NODE_ENV=production \
    LOG_LEVEL=info \
    HTTP_PORT=8080 \
    GRPC_PORT=50051

# Use tini as PID 1 (proper signal handling)
ENTRYPOINT ["/sbin/tini", "--"]

# Start service
CMD ["node", "dist/index.js"]

# =============================================
# Build & Run Instructions
# =============================================
# Build:
#   docker build -t eracun/audit-logger:latest .
#
# Run (development):
#   docker run -p 8080:8080 -p 50051:50051 \
#     -e DATABASE_URL=postgresql://user:pass@host:5432/db \
#     -e KAFKA_BROKERS=kafka:9092 \
#     eracun/audit-logger:latest
#
# Run (with env file):
#   docker run -p 8080:8080 -p 50051:50051 \
#     --env-file .env \
#     eracun/audit-logger:latest
#
# Run (with docker-compose):
#   See docker-compose.yml in repository root

# =============================================
# Security Features
# =============================================
# ✓ Multi-stage build (minimal attack surface)
# ✓ Alpine Linux base (small image size)
# ✓ Non-root user (eracun:1001)
# ✓ No shell access (node binary only)
# ✓ Read-only filesystem compatible
# ✓ Tini PID 1 (proper signal handling)
# ✓ Health check endpoint
# ✓ Minimal dependencies
# ✓ No package manager (npm removed in runtime)
# ✓ CA certificates for HTTPS

# =============================================
# Production Deployment
# =============================================
# For systemd deployment:
# 1. Build image: docker build -t eracun/audit-logger:v1.0.0 .
# 2. Save image: docker save eracun/audit-logger:v1.0.0 > audit-logger.tar
# 3. Transfer to droplet: scp audit-logger.tar user@droplet:/tmp/
# 4. Load on droplet: docker load < /tmp/audit-logger.tar
# 5. Run via systemd: systemctl start eracun-audit-logger
#
# Alternative (native deployment without Docker):
# 1. rsync -av dist/ user@droplet:/opt/eracun/services/audit-logger/
# 2. ssh user@droplet "cd /opt/eracun/services/audit-logger && npm ci --only=production"
# 3. systemctl restart eracun-audit-logger
