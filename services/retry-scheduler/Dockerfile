# Multi-stage Dockerfile for retry-scheduler

FROM node:20-alpine AS builder

RUN apk add --no-cache python3 make g++

WORKDIR /build

COPY package*.json tsconfig.json ./
RUN npm ci

COPY src/ ./src/
RUN npm run build

RUN npm prune --production

FROM node:20-alpine

RUN apk add --no-cache dumb-init

RUN addgroup -g 1001 eracun && \
    adduser -D -u 1001 -G eracun eracun

WORKDIR /app

COPY --from=builder --chown=eracun:eracun /build/dist ./dist
COPY --from=builder --chown=eracun:eracun /build/node_modules ./node_modules
COPY --from=builder --chown=eracun:eracun /build/package.json ./

USER eracun

EXPOSE 8086 9094

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD node -e "require('http').get('http://localhost:8086/health', (res) => { process.exit(res.statusCode === 200 ? 0 : 1); })"

ENTRYPOINT ["/usr/bin/dumb-init", "--"]

CMD ["node", "dist/index.js"]
