FROM node:20-alpine
WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm ci --omit=dev || npm i --omit=dev
COPY src ./src
COPY .env* ./
EXPOSE 4000
CMD ["node", "src/server.js"]
