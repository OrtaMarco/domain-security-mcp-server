# Build stage
FROM node:22-alpine AS build
WORKDIR /app
COPY package*.json ./
# Sin scripts de instalación: la compilación es el `npm run build` de abajo.
RUN npm ci --ignore-scripts
COPY tsconfig.json ./
COPY src ./src
RUN npm run build

# Runtime stage
FROM node:22-alpine
WORKDIR /app
ENV NODE_ENV=production
ENV TRANSPORT=http
ENV PORT=3000
# Inside a container the port is only reachable through the published mapping.
ENV HOST=0.0.0.0
COPY package*.json ./
# dist llega ya compilado de la etapa de build; aquí no corre ningún script.
RUN npm ci --omit=dev --ignore-scripts
COPY --from=build /app/dist ./dist
USER node
EXPOSE 3000
HEALTHCHECK --interval=30s --timeout=5s \
  CMD wget -qO- http://127.0.0.1:3000/healthz || exit 1
CMD ["node", "dist/index.js"]
