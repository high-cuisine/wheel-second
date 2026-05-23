# Build from repository root: wheel-second/
# better-sqlite3 compiles native bindings — need toolchain for npm install
# mirror.gcr.io — Docker Hub cache, avoids anonymous pull rate limits (429)
FROM mirror.gcr.io/library/node:20-bookworm-slim AS deps

RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 make g++ \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /app/server

COPY server/package.json ./
RUN npm install --omit=dev && npm cache clean --force

FROM mirror.gcr.io/library/node:20-bookworm-slim AS runner

WORKDIR /app/server

COPY --from=deps /app/server/node_modules ./node_modules
COPY server/package.json ./
COPY server/src ./src

WORKDIR /app
COPY index.html admin.html ./

WORKDIR /app/server

ENV NODE_ENV=production
EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD node -e "require('http').get('http://127.0.0.1:3000/api/session',(r)=>process.exit(r.statusCode?0:1)).on('error',()=>process.exit(1))"

CMD ["node", "src/index.js"]
