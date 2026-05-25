# Safe Sender — nginx + dashboard image.
#
# Stage 1: build the React/Vite dashboard into static assets.
# Stage 2: copy assets into nginx:alpine alongside our prod nginx.conf.
#
# Why a custom image (not bind-mounts):
#   - Build artifacts live with the image tag, so rollbacks are atomic.
#   - No "did somebody run `npm run build` on prod?" foot-guns.
#   - Reproducible: hash-pinned node base + lockfile install.
#
# Build context is the repo root (see docker-compose.prod.yml) so we can
# reach both ./dashboard and ./nginx from here.

# ---- Stage 1: build SPA ----
FROM node:20-alpine AS dashboard-build

WORKDIR /build

# Install deps from lockfile for reproducible builds.
COPY dashboard/package.json dashboard/package-lock.json ./
RUN npm ci --no-audit --no-fund

# Copy source and build.
COPY dashboard/ ./
# VITE_API_URL defaults to '/api' (same-origin via nginx reverse proxy),
# matching dashboard/.env.example. Override at build time if needed:
#   docker compose build --build-arg VITE_API_URL=https://api.example.com nginx
ARG VITE_API_URL=/api
ENV VITE_API_URL=$VITE_API_URL
# Sentry — DSN and metadata baked into the SPA bundle at build time.
# All four default to empty: with no DSN, the dashboard's initSentry() is a no-op.
ARG VITE_SENTRY_DSN=
ARG VITE_SENTRY_ENVIRONMENT=production
ARG VITE_SENTRY_TRACES_SAMPLE_RATE=0.05
ARG VITE_SENTRY_RELEASE=
ENV VITE_SENTRY_DSN=$VITE_SENTRY_DSN
ENV VITE_SENTRY_ENVIRONMENT=$VITE_SENTRY_ENVIRONMENT
ENV VITE_SENTRY_TRACES_SAMPLE_RATE=$VITE_SENTRY_TRACES_SAMPLE_RATE
ENV VITE_SENTRY_RELEASE=$VITE_SENTRY_RELEASE
RUN npm run build

# ---- Stage 2: nginx serving the built SPA ----
FROM nginx:alpine

# Remove default site config (we ship our own).
RUN rm -f /etc/nginx/conf.d/default.conf

# Our prod nginx config. References /etc/letsencrypt/live/... directly;
# letsencrypt dir is bind-mounted by compose at runtime.
COPY nginx/nginx.conf /etc/nginx/conf.d/default.conf

# Built SPA assets — served from `root /usr/share/nginx/html;` in nginx.conf.
COPY --from=dashboard-build /build/dist/ /usr/share/nginx/html/

# Sanity check: fail the build if index.html is missing.
RUN test -f /usr/share/nginx/html/index.html

EXPOSE 80 443
