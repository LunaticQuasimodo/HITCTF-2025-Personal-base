FROM oven/bun:1 AS base

FROM base AS deps
WORKDIR /app
COPY package.json bun.lock ./
ENV PUPPETEER_SKIP_CHROMIUM_DOWNLOAD=true
RUN bun install --frozen-lockfile

FROM base AS builder
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY . .

ENV PUPPETEER_SKIP_CHROMIUM_DOWNLOAD=true
RUN bun run build

FROM node:20-alpine AS runner
WORKDIR /app

ENV NODE_ENV production
RUN apk add --no-cache nginx chromium

ENV PUPPETEER_SKIP_CHROMIUM_DOWNLOAD=true
ENV PUPPETEER_EXECUTABLE_PATH=/usr/bin/chromium-browser

COPY nginx.conf /etc/nginx/nginx.conf

COPY --from=builder /app/public ./public

COPY --from=builder /app/.next/standalone ./
COPY --from=builder /app/.next/static ./.next/static

# Copy entrypoint script
COPY entrypoint.sh ./entrypoint.sh
RUN chmod +x ./entrypoint.sh

EXPOSE 80

CMD ["./entrypoint.sh"]
