# Multi-stage Dockerfile for KPD Registry Sync Service

# Stage 1: Build
FROM node:20-alpine AS builder

WORKDIR /app

# Install dependencies
COPY package*.json ./
RUN npm ci --only=production && \
    npm install typescript @types/node --save-dev

# Copy source code
COPY tsconfig.json ./
COPY src/ ./src/
COPY proto/ ./proto/

# Build TypeScript
RUN npm run build

# Stage 2: Production
FROM node:20-alpine

# Install dumb-init (proper signal handling)
RUN apk add --no-cache dumb-init

# Create non-root user
RUN addgroup -g 1001 eracun && \
    adduser -u 1001 -G eracun -s /bin/sh -D eracun

WORKDIR /app

# Copy production dependencies
COPY package*.json ./
RUN npm ci --only=production

# Copy built application from builder
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/proto ./proto

# Set ownership
RUN chown -R eracun:eracun /app

# Switch to non-root user
USER eracun

# Expose ports
EXPOSE 8088 50052 9093

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
  CMD node -e "require('http').get('http://localhost:8088/health', (r) => { process.exit(r.statusCode === 200 ? 0 : 1); }).on('error', () => process.exit(1));"

# Use dumb-init to handle signals properly
ENTRYPOINT ["dumb-init", "--"]

# Start application
CMD ["node", "dist/index.js"]
