FROM node:20-alpine

# Use non-root user
RUN addgroup -S trustgroup && adduser -S trustuser -G trustgroup

WORKDIR /usr/src/app

# Only copy package files first for caching
COPY package*.json ./

# Install production dependencies
RUN npm ci --omit=dev

# Copy application files
COPY . .

# Ensure uploads dir exists and has right permissions
RUN mkdir -p uploads && chown -R trustuser:trustgroup .

USER trustuser

EXPOSE 3000

# Set environment to production
ENV NODE_ENV=production
ENV PORT=3000

CMD ["node", "server.js"]
