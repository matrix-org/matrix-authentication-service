# syntax = docker/dockerfile:1.4

# Builds a minimal image with the binary only. It is multi-arch capable,
# cross-building to aarch64 and x86_64. When cross-compiling, Docker sets two
# implicit BUILDARG: BUILDPLATFORM being the host platform and TARGETPLATFORM
# being the platform being built.
#
# Docker platform definitions look like this: linux/arm64 and linux/amd64, so
# there is a small script that translates those platforms to LLVM triples,
# respectively x86-64-unknown-linux-gnu and aarch64-unknown-linux-gnu

# The Debian version and version name must be in sync
ARG DEBIAN_VERSION=11
ARG DEBIAN_VERSION_NAME=bullseye
ARG RUSTC_VERSION=1.65.0
ARG ZIG_VERSION=0.9.1
ARG NODEJS_VERSION=18
ARG OPA_VERSION=0.45.0

##########################################
## Build stage that builds the frontend ##
##########################################

FROM --platform=${BUILDPLATFORM} docker.io/library/node:${NODEJS_VERSION}-${DEBIAN_VERSION_NAME}-slim AS frontend

WORKDIR /app/frontend

COPY ./frontend/package.json ./frontend/package-lock.json /app/frontend/
RUN npm ci

COPY ./frontend/ /app/frontend/
COPY ./templates/ /app/templates/
RUN npm run build

# Move the built files
RUN \
  mkdir -p /share/assets && \
  cp ./dist/manifest.json /share/manifest.json && \
  rm -f ./dist/index.html* ./dist/manifest.json* && \
  cp ./dist/* /share/assets/

##############################################
## Build stage that builds the OPA policies ##
##############################################

FROM --platform=${BUILDPLATFORM} docker.io/library/debian:${DEBIAN_VERSION_NAME}-slim AS policy

# Install make
RUN apt update && apt install -y --no-install-recommends make

ARG BUILDOS
ARG BUILDARCH
ARG OPA_VERSION

# Download Open Policy Agent
ADD --chmod=755 https://github.com/open-policy-agent/opa/releases/download/v${OPA_VERSION}/opa_${BUILDOS}_${BUILDARCH}_static /usr/local/bin/opa

WORKDIR /app/policies
COPY ./policies /app/policies
RUN make -B
RUN chmod a+r ./policy.wasm

##########################################################################
## Base image with cargo-chef and the right cross-compilation toolchain ##
##########################################################################

FROM --platform=${BUILDPLATFORM} docker.io/library/rust:${RUSTC_VERSION}-slim-${DEBIAN_VERSION_NAME} AS toolchain

ARG ZIG_VERSION
ARG RUSTC_VERSION

# Make cargo use the git cli for fetching dependencies
ENV CARGO_NET_GIT_FETCH_WITH_CLI=true

# Install the protobuf compiler, git, curl and xz
RUN apt update && apt install -y --no-install-recommends \
  git \
  curl \
  xz-utils \
  protobuf-compiler

# Download zig compiler for cross-compilation
RUN curl -L "https://ziglang.org/download/${ZIG_VERSION}/zig-linux-$(uname -m)-${ZIG_VERSION}.tar.xz" | tar -J -x -C /usr/local && \
  ln -s "/usr/local/zig-linux-$(uname -m)-${ZIG_VERSION}/zig" /usr/local/bin/zig

WORKDIR /app
RUN cargo install --locked cargo-chef cargo-zigbuild cargo-auditable

# Install all cross-compilation targets
RUN rustup target add --toolchain "${RUSTC_VERSION}" \
  x86_64-unknown-linux-gnu \
  aarch64-unknown-linux-gnu

# Helper script that transforms docker platforms to LLVM triples
COPY ./misc/docker-arch-to-rust-target.sh /

#####################################
## Run the planner from cargo-chef ##
#####################################

FROM --platform=${BUILDPLATFORM} toolchain AS planner
COPY ./Cargo.toml ./Cargo.lock /app/
COPY ./crates /app/crates
RUN cargo chef prepare --recipe-path recipe.json --bin crates/cli

########################
## Actual build stage ##
########################

FROM --platform=${BUILDPLATFORM} toolchain AS builder

ARG TARGETPLATFORM

# Build dependencies
COPY --from=planner /app/recipe.json recipe.json
RUN cargo chef cook \
  --zigbuild \
  --bin mas-cli \
  --release \
  --recipe-path recipe.json \
  --no-default-features \
  --features docker \
  --target $(/docker-arch-to-rust-target.sh "${TARGETPLATFORM}") \
  --package mas-cli

# Build the rest
COPY ./Cargo.toml ./Cargo.lock /app/
COPY ./crates /app/crates
ENV SQLX_OFFLINE=true
RUN cargo auditable zigbuild \
  --locked \
  --release \
  --bin mas-cli \
  --no-default-features \
  --features docker \
  --target $(/docker-arch-to-rust-target.sh "${TARGETPLATFORM}")

# Move the binary to avoid having to guess its name in the next stage
RUN mv target/$(/docker-arch-to-rust-target.sh "${TARGETPLATFORM}")/release/mas-cli /usr/local/bin/mas-cli

#######################################
## Prepare /usr/local/share/mas-cli/ ##
#######################################
FROM --platform=${BUILDPLATFORM} scratch AS share

COPY --from=frontend /share /share
COPY --from=policy /app/policies/policy.wasm /share/policy.wasm
COPY ./templates/ /share/templates

##################################
## Runtime stage, debug variant ##
##################################
FROM --platform=${TARGETPLATFORM} gcr.io/distroless/cc-debian${DEBIAN_VERSION}:debug-nonroot AS debug

COPY --from=builder /usr/local/bin/mas-cli /usr/local/bin/mas-cli
COPY --from=share /share /usr/local/share/mas-cli

WORKDIR /
ENTRYPOINT ["/usr/local/bin/mas-cli"]

###################
## Runtime stage ##
###################
FROM --platform=${TARGETPLATFORM} gcr.io/distroless/cc-debian${DEBIAN_VERSION}:nonroot

COPY --from=builder /usr/local/bin/mas-cli /usr/local/bin/mas-cli
COPY --from=share /share /usr/local/share/mas-cli

WORKDIR /
ENTRYPOINT ["/usr/local/bin/mas-cli"]
