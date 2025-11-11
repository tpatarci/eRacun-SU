# Multi-stage Dockerfile for notification-service
# Stage 1: Build (compile TypeScript)
# Stage 2: Production (minimal runtime)

# =============================================================================
# STAGE 1: BUILD
# =============================================================================
FROM node:20-alpine AS builder

# Install build dependencies
RUN apk add --no-cache python3 make g++

# Set working directory
WORKDIR /build

# Copy package files
COPY package*.json ./
COPY tsconfig.json ./

# Install dependencies (including devDependencies for build)
RUN npm ci

# Copy source code
COPY src/ ./src/
COPY templates/ ./templates/

# Build TypeScript
RUN npm run build

# Prune dev dependencies
RUN npm prune --production

# =============================================================================
# STAGE 2: PRODUCTION
# =============================================================================
FROM node:20-alpine

# Install dumb-init (proper signal handling)
RUN apk add --no-cache dumb-init

# Create non-root user
RUN addgroup -g 1001 eracun && \
    adduser -D -u 1001 -G eracun eracun

# Set working directory
WORKDIR /app

# Copy built application from builder
COPY --from=builder --chown=eracun:eracun /build/dist ./dist
COPY --from=builder --chown=eracun:eracun /build/node_modules ./node_modules
COPY --from=builder --chown=eracun:eracun /build/package.json ./
COPY --from=builder --chown=eracun:eracun /build/templates ./templates

# Switch to non-root user
USER eracun

# Expose ports
EXPOSE 8085 9093

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD node -e "require('http').get('http://localhost:8085/health', (res) => { process.exit(res.statusCode === 200 ? 0 : 1); })"

# Use dumb-init to handle signals properly
ENTRYPOINT ["/usr/bin/dumb-init", "--"]

# Start service
CMD ["node", "dist/index.js"]
