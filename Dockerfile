# syntax=docker/dockerfile:1
# ============================================================
# Stage 1 – build
#   Installs all dependencies and compiles every TypeScript
#   workspace package (sanctions-oracle, horizon-listener, …)
#   into their respective dist/ directories.
# ============================================================
FROM node:20-alpine AS builder

WORKDIR /app

# Copy manifests first for better layer caching
COPY package.json package-lock.json ./
COPY backoff/package.json            backoff/package.json
COPY logger/package.json             logger/package.json
COPY shared/package.json             shared/package.json
COPY tracing-types/package.json      tracing-types/package.json
COPY metrics/package.json            metrics/package.json
COPY tracing/package.json            tracing/package.json
COPY sep10-auth/package.json         sep10-auth/package.json
COPY sanctions-oracle/package.json   sanctions-oracle/package.json
COPY horizon-listener/package.json   horizon-listener/package.json

# Install all dependencies (including devDependencies needed for tsc)
RUN npm ci --ignore-scripts

# Copy source trees
COPY tsconfig.base.json ./
COPY backoff/            backoff/
COPY logger/             logger/
COPY shared/             shared/
COPY tracing-types/      tracing-types/
COPY metrics/            metrics/
COPY tracing/            tracing/
COPY sep10-auth/         sep10-auth/
COPY sanctions-oracle/   sanctions-oracle/
COPY horizon-listener/   horizon-listener/

# Compile all packages
RUN npm run build

# ============================================================
# Stage 2 – runtime (slim alpine image, non-root user)
#   Copies only the compiled output and production deps.
#   Does NOT include TypeScript sources, devDependencies, or
#   build tooling.
# ============================================================
FROM node:20-alpine AS runtime

# Security: run as a dedicated non-root user
RUN addgroup -S appgroup && adduser -S appuser -G appgroup

WORKDIR /app

# Copy production manifests
COPY package.json package-lock.json ./
COPY backoff/package.json            backoff/package.json
COPY logger/package.json             logger/package.json
COPY shared/package.json             shared/package.json
COPY tracing-types/package.json      tracing-types/package.json
COPY metrics/package.json            metrics/package.json
COPY tracing/package.json            tracing/package.json
COPY sep10-auth/package.json         sep10-auth/package.json
COPY sanctions-oracle/package.json   sanctions-oracle/package.json
COPY horizon-listener/package.json   horizon-listener/package.json

# Install production dependencies only
RUN npm ci --omit=dev --ignore-scripts

# Copy compiled dist/ output from the builder stage
COPY --from=builder /app/backoff/dist/       backoff/dist/
COPY --from=builder /app/logger/dist/        logger/dist/
COPY --from=builder /app/shared/dist/        shared/dist/
COPY --from=builder /app/tracing-types/dist/ tracing-types/dist/
COPY --from=builder /app/metrics/dist/       metrics/dist/
COPY --from=builder /app/tracing/dist/       tracing/dist/
COPY --from=builder /app/sep10-auth/dist/    sep10-auth/dist/
COPY --from=builder /app/sanctions-oracle/dist/  sanctions-oracle/dist/
COPY --from=builder /app/horizon-listener/dist/  horizon-listener/dist/

# Copy the CLI entry point
COPY bin/ bin/

# Transfer ownership to the non-root user
RUN chown -R appuser:appgroup /app

USER appuser

# Smoke-test: ensure the CLI starts and --help exits cleanly
RUN node bin/compliance-adapters.js --help

ENTRYPOINT ["node", "bin/compliance-adapters.js"]
CMD ["--help"]
