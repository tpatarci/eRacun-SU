# Multi-stage Dockerfile for health-monitor service
FROM node:20-alpine AS builder
WORKDIR /app
COPY package*.json tsconfig.json ./
RUN npm ci
COPY src ./src
COPY config ./config
RUN npm run build

FROM node:20-alpine AS runtime
RUN addgroup -g 1001 -S eracun && adduser -S eracun -u 1001 -G eracun
WORKDIR /app
COPY --from=builder --chown=eracun:eracun /app/dist ./dist
COPY --from=builder --chown=eracun:eracun /app/node_modules ./node_modules
COPY --from=builder --chown=eracun:eracun /app/config ./config
COPY --chown=eracun:eracun package.json ./
USER eracun
EXPOSE 8084
HEALTHCHECK --interval=30s --timeout=5s CMD node -e "require('http').get('http://localhost:8084/health', (r) => process.exit(r.statusCode === 200 ? 0 : 1))"
CMD ["node", "dist/index.js"]
