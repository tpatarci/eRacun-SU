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

# Create maildir
RUN mkdir -p /app/maildir

# Expose ports
EXPOSE 1025 1143 8025

# Start service
CMD ["node", "dist/server.js"]
