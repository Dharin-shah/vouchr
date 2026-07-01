# syntax=docker/dockerfile:1
# Standalone headless Vouchr broker. Base images are ARGs so a platform can pin its own
# (e.g. an internal ECR mirror): --build-arg BUILD_IMAGE=... --build-arg RUNTIME_IMAGE=...
ARG BUILD_IMAGE=node:22-bookworm
ARG RUNTIME_IMAGE=node:22-bookworm-slim

FROM ${BUILD_IMAGE} AS build
WORKDIR /app
# Install with the lockfile first for a cached dependency layer (better-sqlite3 compiles here).
COPY package.json package-lock.json ./
RUN npm ci
COPY . .
RUN npm run build && npm prune --omit=dev

FROM ${RUNTIME_IMAGE} AS runtime
ENV NODE_ENV=production
WORKDIR /app
COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/dist ./dist
COPY --from=build /app/package.json ./package.json
# For KMS-backed deployments, insert this before USER node:
#   RUN npm install --no-save @aws-sdk/client-kms && npm cache clean --force
USER node
EXPOSE 3000
# Liveness without curl: hit /healthz over loopback and exit non-zero on failure.
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 CMD \
  node -e "require('http').get({host:'127.0.0.1',port:process.env.VOUCHR_PORT||3000,path:'/healthz'},r=>process.exit(r.statusCode===200?0:1)).on('error',()=>process.exit(1))"
CMD ["node", "dist/bin/broker-server.js"]
