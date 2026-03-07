# ============================================================
# Stage 1: Build
# ============================================================
FROM node:20-alpine AS builder

WORKDIR /app

# Install dependencies first (layer caching)
COPY package.json package-lock.json* ./
RUN npm ci --silent

# Copy source and build
COPY . .

# Build args for runtime API base URL
ARG VITE_API_BASE_URL=""
ENV VITE_API_BASE_URL=$VITE_API_BASE_URL

RUN npm run build


# ============================================================
# Stage 2: Serve with nginx
# ============================================================
FROM nginx:1.27-alpine AS runtime

LABEL maintainer="SecureErase Pro <noreply@example.com>"
LABEL description="SecureErase Pro — Verification Portal Frontend"

# Remove default nginx site
RUN rm -rf /usr/share/nginx/html/*

# Copy built assets
COPY --from=builder /app/dist /usr/share/nginx/html

# nginx config: SPA routing (all paths → index.html)
RUN printf 'server {\n\
    listen 80;\n\
    listen [::]:80;\n\
    root /usr/share/nginx/html;\n\
    index index.html;\n\
    # Security headers\n\
    add_header X-Frame-Options DENY;\n\
    add_header X-Content-Type-Options nosniff;\n\
    add_header Referrer-Policy strict-origin-when-cross-origin;\n\
    # SPA fallback\n\
    location / {\n\
        try_files $uri $uri/ /index.html;\n\
    }\n\
    # Static asset caching\n\
    location ~* \\.(js|css|png|svg|ico|woff2?)$ {\n\
        expires 1y;\n\
        add_header Cache-Control "public, immutable";\n\
    }\n\
    # Health probe\n\
    location /healthz {\n\
        return 200 "ok";\n\
        add_header Content-Type text/plain;\n\
    }\n\
}\n' > /etc/nginx/conf.d/default.conf

EXPOSE 80

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD wget -qO- http://localhost/healthz || exit 1

CMD ["nginx", "-g", "daemon off;"]
