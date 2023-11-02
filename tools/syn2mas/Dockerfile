
# Build Node.js app
FROM --platform=${BUILDPLATFORM} node:18-alpine AS builder

WORKDIR /syn2mas

COPY ./package.json ./package-lock.json ./
RUN --network=default \
  npm ci --ignore-scripts

COPY ./tsconfig.json ./
COPY ./src ./src/

RUN --network=none \
  npm run prepare

# Put together a runtime image
FROM --platform=${BUILDPLATFORM} node:18-alpine

WORKDIR /syn2mas

COPY ./package.json ./package-lock.json ./
RUN --network=default \
  npm ci --omit=dev --ignore-scripts

COPY --from=builder /syn2mas/dist ./dist

ENTRYPOINT ["node", "dist/index.js"]
