FROM node:24-bookworm-slim

WORKDIR /app/wonchang

COPY wonchang/package.json wonchang/package-lock.json ./
RUN npm ci --omit=dev --no-audit --no-fund

COPY --chown=node:node wonchang/src/ ./src/
COPY --chown=node:node wonchang/views/ ./views/
COPY --chown=node:node src/db.mjs src/sites.mjs /app/src/
COPY --chown=node:node public/ /app/public/
RUN install -d -o node -g node /app/data

ENV NODE_ENV=production HOST=0.0.0.0 PORT=4102
USER node
EXPOSE 4102

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:4102/').then(r => process.exit(r.ok ? 0 : 1)).catch(() => process.exit(1))"

CMD ["node", "src/server.mjs"]
