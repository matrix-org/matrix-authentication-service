# syntax = docker/dockerfile:1.6

# Builds a minimal image with the binary only. It is multi-arch capable,
# cross-building to aarch64 and x86_64. When cross-compiling, Docker sets two
# implicit BUILDARG: BUILDPLATFORM being the host platform and TARGETPLATFORM
# being the platform being built.

# The Debian version and version name must be in sync
ARG DEBIAN_VERSION=12
ARG DEBIAN_VERSION_NAME=bookworm
ARG RUSTC_VERSION=1.76.0
# XXX: Upgrade to 0.10.0 blocked by https://github.com/ziglang/zig/issues/10915#issuecomment-1354548110
# XXX: Upgrade to 0.11.0 blocked by https://github.com/rust-cross/cargo-zigbuild/issues/162
ARG ZIG_VERSION=0.9.1
ARG NODEJS_VERSION=20.9.0
ARG OPA_VERSION=0.59.0
ARG CARGO_AUDITABLE_VERSION=0.6.2
ARG CARGO_CHEF_VERSION=0.1.64
ARG CARGO_ZIGBUILD_VERSION=0.18.3

##########################################
## Build stage that builds the frontend ##
##########################################
FROM --platform=${BUILDPLATFORM} docker.io/library/node:${NODEJS_VERSION}-${DEBIAN_VERSION_NAME} AS frontend

WORKDIR /app/frontend

COPY ./frontend/package.json ./frontend/package-lock.json /app/frontend/
# Network access: to fetch dependencies
RUN --network=default \
  npm ci

COPY ./frontend/ /app/frontend/
COPY ./templates/ /app/templates/
RUN --network=none \
  npm run build

# Move the built files
RUN --network=none \
  mkdir -p /share/assets && \
  cp ./dist/manifest.json /share/manifest.json && \
  rm -f ./dist/index.html* ./dist/manifest.json* && \
  cp ./dist/* /share/assets/

##############################################
## Build stage that builds the OPA policies ##
##############################################
FROM --platform=${BUILDPLATFORM} docker.io/library/buildpack-deps:${DEBIAN_VERSION_NAME} AS policy

ARG BUILDOS
ARG BUILDARCH
ARG OPA_VERSION

# Download Open Policy Agent
ADD --chmod=755 https://github.com/open-policy-agent/opa/releases/download/v${OPA_VERSION}/opa_${BUILDOS}_${BUILDARCH}_static /usr/local/bin/opa

WORKDIR /app/policies
COPY ./policies /app/policies
RUN --network=none  \
  make -B && \
  chmod a+r ./policy.wasm

##########################################################################
## Base image with cargo-chef and the right cross-compilation toolchain ##
##########################################################################
FROM --platform=${BUILDPLATFORM} docker.io/library/rust:${RUSTC_VERSION}-${DEBIAN_VERSION_NAME} AS toolchain

ARG CARGO_AUDITABLE_VERSION
ARG CARGO_CHEF_VERSION
ARG CARGO_ZIGBUILD_VERSION
ARG RUSTC_VERSION
ARG ZIG_VERSION

# Make cargo use the git cli for fetching dependencies
ENV CARGO_NET_GIT_FETCH_WITH_CLI=true

# Install pinned versions of cargo-chef, cargo-zigbuild and cargo-auditable
# Network access: to fetch dependencies
RUN --network=default \
  cargo install --locked \
  cargo-chef@=${CARGO_CHEF_VERSION} \
  cargo-zigbuild@=${CARGO_ZIGBUILD_VERSION} \
  cargo-auditable@=${CARGO_AUDITABLE_VERSION}

# Download zig compiler for cross-compilation
# Network access: to download zig
RUN --network=default \
  curl -L "https://ziglang.org/download/${ZIG_VERSION}/zig-linux-$(uname -m)-${ZIG_VERSION}.tar.xz" | tar -J -x -C /usr/local && \
  ln -s "/usr/local/zig-linux-$(uname -m)-${ZIG_VERSION}/zig" /usr/local/bin/zig

# Install all cross-compilation targets
# Network access: to download the targets
RUN --network=default \
  rustup target add  \
  --toolchain "${RUSTC_VERSION}" \
  x86_64-unknown-linux-musl \
  aarch64-unknown-linux-musl

# Set the working directory
WORKDIR /app

#####################################
## Run the planner from cargo-chef ##
#####################################
FROM --platform=${BUILDPLATFORM} toolchain AS planner
COPY ./Cargo.toml ./Cargo.lock /app/
COPY ./crates /app/crates
RUN --network=none \
  cargo chef prepare --recipe-path recipe.json --bin crates/cli

########################
## Actual build stage ##
########################
FROM --platform=${BUILDPLATFORM} toolchain AS builder

# Build dependencies
COPY --from=planner /app/recipe.json recipe.json
# Network access: cargo-chef cook fetches the dependencies
RUN --network=default \
  cargo chef cook \
  --zigbuild \
  --bin mas-cli \
  --release \
  --recipe-path recipe.json \
  --no-default-features \
  --features docker \
  --target x86_64-unknown-linux-musl \
  --target aarch64-unknown-linux-musl \
  --package mas-cli

# Build the rest
COPY ./Cargo.toml ./Cargo.lock /app/
COPY ./crates /app/crates
ENV SQLX_OFFLINE=true
# Network access: cargo auditable needs it
RUN --network=default \
  cargo auditable zigbuild \
  --locked \
  --release \
  --bin mas-cli \
  --no-default-features \
  --features docker \
  --target x86_64-unknown-linux-musl \
  --target aarch64-unknown-linux-musl

# Move the binary to avoid having to guess its name in the next stage
RUN --network=none \
  mv "target/x86_64-unknown-linux-musl/release/mas-cli" /usr/local/bin/mas-cli-amd64
RUN --network=none \
  mv "target/aarch64-unknown-linux-musl/release/mas-cli" /usr/local/bin/mas-cli-arm64

#######################################
## Prepare /usr/local/share/mas-cli/ ##
#######################################
FROM --platform=${BUILDPLATFORM} scratch AS share

COPY --from=frontend /share /share
COPY --from=policy /app/policies/policy.wasm /share/policy.wasm
COPY ./templates/ /share/templates
COPY ./translations/ /share/translations

##################################
## Runtime stage, debug variant ##
##################################
FROM --platform=${TARGETPLATFORM} gcr.io/distroless/static-debian${DEBIAN_VERSION}:debug-nonroot AS debug

ARG TARGETARCH
COPY --from=builder /usr/local/bin/mas-cli-${TARGETARCH} /usr/local/bin/mas-cli
COPY --from=share /share /usr/local/share/mas-cli

WORKDIR /
ENTRYPOINT ["/usr/local/bin/mas-cli"]

###################
## Runtime stage ##
###################
FROM --platform=${TARGETPLATFORM} gcr.io/distroless/static-debian${DEBIAN_VERSION}:nonroot

ARG TARGETARCH
COPY --from=builder /usr/local/bin/mas-cli-${TARGETARCH} /usr/local/bin/mas-cli
COPY --from=share /share /usr/local/share/mas-cli

WORKDIR /
ENTRYPOINT ["/usr/local/bin/mas-cli"]
