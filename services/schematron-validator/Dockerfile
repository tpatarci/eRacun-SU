# Schematron Validator Service - Production Dockerfile
#
# Multi-stage build for minimal production image

# ============================================================================
# Stage 1: Build
# ============================================================================

FROM node:20-alpine AS builder

# Install build dependencies
# Note: Saxon-JS is pure JavaScript, no native dependencies required
RUN apk add --no-cache \
    python3 \
    make \
    g++

WORKDIR /app

# Copy package files
COPY package*.json ./
COPY tsconfig.json ./

# Install dependencies (including devDependencies for build)
RUN npm ci

# Copy source code
COPY src/ ./src/
COPY rules/ ./rules/

# Build TypeScript
RUN npm run build

# ============================================================================
# Stage 2: Production
# ============================================================================

FROM node:20-alpine

# Add non-root user
RUN addgroup -g 1000 eracun && \
    adduser -D -u 1000 -G eracun eracun

WORKDIR /app

# Copy package files
COPY package*.json ./

# Install production dependencies only
RUN npm ci --only=production && \
    npm cache clean --force

# Copy built code from builder
COPY --from=builder /app/dist ./dist/
COPY --from=builder /app/rules ./rules/

# Set ownership
RUN chown -R eracun:eracun /app

# Switch to non-root user
USER eracun

# Expose ports
EXPOSE 8081 9101

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD node -e "require('http').get('http://localhost:8081/health', (res) => { process.exit(res.statusCode === 200 ? 0 : 1); }).on('error', () => process.exit(1));"

# Start service
CMD ["node", "dist/index.js"]
