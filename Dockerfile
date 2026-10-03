FROM node:24-alpine
ENV NODE_ENV=production
ENV HOST=0.0.0.0
ENV PORT=3000
ENV DATABASE_PATH=/data/users.sqlite
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts
COPY server.js index.html ./
RUN mkdir -p /data && chown -R node:node /app /data
EXPOSE 3000
USER node
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
	CMD node -e "fetch('http://127.0.0.1:3000/healthz').then(r => process.exit(r.ok ? 0 : 1)).catch(() => process.exit(1))"
CMD ["node", "server.js"]
