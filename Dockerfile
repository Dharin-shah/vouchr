# syntax=docker/dockerfile:1
# Standalone headless Vouchr broker. Base images are ARGs so a platform can pin its own
# (e.g. an internal ECR mirror): --build-arg BUILD_IMAGE=... --build-arg RUNTIME_IMAGE=...
ARG BUILD_IMAGE=node:22-bookworm
ARG RUNTIME_IMAGE=node:22-bookworm-slim

FROM ${BUILD_IMAGE} AS build
WORKDIR /app
# Install with the lockfile first for a cached dependency layer.
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
# For KMS-backed deployments, insert this before the USER line:
#   RUN npm install --no-save @aws-sdk/client-kms && npm cache clean --force
# A numeric USER has no /etc/passwd name lookup, so Docker does not set HOME for it — set it
# explicitly to the node user's home (owned by uid 1000) so tooling that reads HOME works. An
# arbitrary-UID platform override lands on `/` for HOME; the broker writes nothing there.
ENV HOME=/home/node
# Numeric non-root user (the official Node image's `node` is uid:gid 1000:1000). A NUMERIC id lets
# the kubelet verify `runAsNonRoot` from the image config alone, so no manifest UID is required —
# `USER node` (a name) cannot be verified and fails closed as CreateContainerConfigError. Restricted
# platforms that allocate a namespace UID range still override this with their own numeric runAsUser.
USER 1000:1000
EXPOSE 3000
# Liveness without curl: hit /healthz over loopback and exit non-zero on failure.
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 CMD \
  node -e "require('http').get({host:'127.0.0.1',port:process.env.VOUCHR_PORT||3000,path:'/healthz'},r=>process.exit(r.statusCode===200?0:1)).on('error',()=>process.exit(1))"
CMD ["node", "dist/bin/broker-server.js"]
