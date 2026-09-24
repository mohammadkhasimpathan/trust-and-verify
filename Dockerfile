FROM node:22-bookworm-slim

# Install native build prerequisites required by better-sqlite3 / node-gyp
RUN apt-get update && \
    apt-get install -y --no-install-recommends python3 make g++ && \
    rm -rf /var/lib/apt/lists/*

# Use non-root user (Debian syntax)
RUN groupadd -r trustgroup && useradd -r -g trustgroup trustuser

WORKDIR /usr/src/app

# Only copy package files first for caching
COPY package*.json ./

# Install production dependencies
RUN npm ci --omit=dev

# Copy application files
COPY . .

# Ensure uploads and data dir exist and have right permissions
RUN mkdir -p uploads data && chown -R trustuser:trustgroup .

USER trustuser

EXPOSE 3000

# Set environment to production
ENV NODE_ENV=production

CMD ["node", "server.js"]
