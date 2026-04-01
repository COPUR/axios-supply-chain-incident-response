FROM node:20-alpine

WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts

COPY src ./src
COPY agent ./agent

CMD ["node", "/app/agent/security-agent.js"]
