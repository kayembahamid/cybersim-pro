# Multi-stage build for CyberSim Pro MCP server

FROM node:20-alpine AS deps
WORKDIR /app

# Install dependencies
COPY package.json package-lock.json ./
RUN npm ci --ignore-scripts

FROM deps AS build
# Copy sources and build
COPY tsconfig.json ./
COPY src ./src
RUN npm run build

# Prune dev dependencies for a smaller runtime image
RUN npm prune --omit=dev

FROM node:20-alpine AS runner
WORKDIR /app
ENV NODE_ENV=production
ARG BUILD_VERSION=1.0.0
ARG BUILD_CREATED
ARG VCS_REF

LABEL org.opencontainers.image.title="cybersim-pro-mcp" \
      org.opencontainers.image.description="CyberSim Pro – MCP server for cybersecurity training, simulation, IR and forensics" \
      org.opencontainers.image.url="https://github.com/kayembahamid/cybersim-pro" \
      org.opencontainers.image.source="https://github.com/kayembahamid/cybersim-pro" \
      org.opencontainers.image.version="$BUILD_VERSION" \
      org.opencontainers.image.revision="$VCS_REF" \
      org.opencontainers.image.created="$BUILD_CREATED" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.vendor="CyberSim Pro" \
      org.opencontainers.image.authors="kayembahamid" \
      io.modelcontextprotocol.server.name="io.github.kayembahamid/cybersim-pro"

# Copy runtime artifacts
COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/build ./build
COPY package.json ./
COPY scripts ./scripts

# HTTP bridge port (only used when CYBERSIM_MODE=http)
EXPOSE 8787

# Select stdio (MCP) or HTTP via env:
#   CYBERSIM_MODE=stdio (default) -> node build/index.js
#   CYBERSIM_MODE=http            -> node build/httpServer.js
ENV CYBERSIM_MODE=stdio

RUN chmod +x ./scripts/docker-entry.sh || true

ENTRYPOINT ["./scripts/docker-entry.sh"]
CMD []
