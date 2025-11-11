# Multi-stage build for minimal production image

# Stage 1: Build
FROM node:20-alpine AS builder

# Install build dependencies for native modules (libxmljs2)
RUN apk add --no-cache python3 make g++ libxml2-dev

WORKDIR /build

# Copy package files
COPY package*.json ./
COPY tsconfig.json ./

# Install dependencies
RUN npm ci --only=production && \
    npm cache clean --force

# Copy source code
COPY src/ ./src/

# Build TypeScript
RUN npm run build

# Stage 2: Runtime
FROM node:20-alpine

# Install runtime dependencies only
RUN apk add --no-cache libxml2 && \
    addgroup -g 1000 eracun && \
    adduser -D -u 1000 -G eracun eracun

WORKDIR /app

# Copy built artifacts from builder
COPY --from=builder /build/dist ./dist
COPY --from=builder /build/node_modules ./node_modules
COPY --from=builder /build/package.json ./

# Copy UBL schemas (will be replaced by volume mount in production)
COPY schemas/ ./schemas/

# Set ownership
RUN chown -R eracun:eracun /app

# Switch to non-root user
USER eracun

# Expose health check and metrics ports
EXPOSE 8080 9100

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD node -e "require('http').get('http://localhost:8080/health', (r) => process.exit(r.statusCode === 200 ? 0 : 1))"

# Start service
CMD ["node", "dist/index.js"]
