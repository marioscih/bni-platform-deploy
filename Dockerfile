FROM node:22.22.0-bookworm-slim

ENV NODE_ENV=production
WORKDIR /opt/bni-platform

COPY package.json package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts && npm cache clean --force

COPY src ./src
COPY db ./db

USER node
EXPOSE 8789
CMD ["node", "src/server.mjs"]
