FROM node:24.19.0-bookworm-slim

WORKDIR /app
COPY --chown=node:node server.js ./server.js
COPY --chown=node:node public/ ./public/

ENV NODE_ENV=production HOST=0.0.0.0 PORT=3000 BOARD_DATA_FILE=/app/data/posts.json
USER node
EXPOSE 3000

HEALTHCHECK --interval=10s --timeout=3s --start-period=10s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:3000/api/posts').then(r => process.exit(r.ok ? 0 : 1)).catch(() => process.exit(1))"

CMD ["node", "server.js"]
