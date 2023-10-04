
# Build Node.js app
FROM --platform=${BUILDPLATFORM} node:18-alpine AS builder

WORKDIR /syn2mas

COPY ./package.json ./package-lock.json ./
RUN npm ci

COPY ./tsconfig.json ./
COPY ./src ./src/

RUN npm run build

# Put together a runtime image
FROM --platform=${BUILDPLATFORM} node:18-alpine

WORKDIR /syn2mas

COPY ./package.json ./package-lock.json ./
RUN npm ci --omit=dev

COPY --from=builder /syn2mas/dist ./dist

ENTRYPOINT ["node", "dist/index.js"]
