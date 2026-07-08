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

# Owner performance dashboard — served at /owner/
# Kept outside the SPA root so it is never part of the React app bundle.
RUN mkdir -p /usr/share/nginx/html/owner
COPY nginx/owner-dashboard.html /usr/share/nginx/html/owner/index.html
RUN chmod 644 /usr/share/nginx/html/owner/index.html

EXPOSE 80 443
