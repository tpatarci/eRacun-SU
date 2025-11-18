FROM node:20-alpine

WORKDIR /app

# Copy package files
COPY package*.json ./
COPY tsconfig.json ./

# Install dependencies
RUN npm ci

# Copy source code
COPY src ./src

# Build
RUN npm run build

# Remove dev dependencies
RUN npm prune --production

# Create cert storage
RUN mkdir -p /app/certs

# Expose port
EXPOSE 8453

# Start service
CMD ["node", "dist/server.js"]
