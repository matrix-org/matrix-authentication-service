# Builds a minimal image with the binary only. It is multi-arch capable,
# cross-building to aarch64 and x86_64. When cross-compiling, Docker sets two
# implicit BUILDARG: BUILDPLATFORM being the host platform and TARGETPLATFORM
# being the platform being built.
#
# Docker platform definitions look like this: linux/arm64 and linux/amd64, so
# there is a small script that translates those platforms to LLVM triples,
# respectively x86-64-unknown-linux-gnu and aarch64-unknown-linux-gnu

ARG RUSTC_VERSION=1.56.1

## Base image with cargo-chef and the right cross-compilation toolchain ##
# cargo-chef helps with caching dependencies between builds
FROM --platform=${BUILDPLATFORM} docker.io/library/rust:${RUSTC_VERSION}-slim AS chef

# Install x86_64 and aarch64 cross-compiling stack
RUN apt update && apt install -y --no-install-recommends \
  g++-x86-64-linux-gnu \
  g++-aarch64-linux-gnu \
  libc6-dev-arm64-cross \
  libc6-dev-amd64-cross \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /app
RUN cargo install --locked cargo-chef

ENV \
  CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc \
  CC_aarch64_unknown_linux_gnu=aarch64-linux-gnu-gcc \
  CXX_aarch64_unknown_linux_gnu=aarch64-linux-gnu-g++ \
  CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=x86_64-linux-gnu-gcc \
  CC_x86_64_unknown_linux_gnu=x86_64-linux-gnu-gcc \
  CXX_x86_64_unknown_linux_gnu=x86_64-linux-gnu-g++

ARG RUSTC_VERSION
ARG TARGETPLATFORM

# Helper script that transforms docker platforms to LLVM triples
COPY ./misc/docker-arch-to-rust-target.sh /
# Install the right toolchain for cross-compilation
RUN rustup target add `/docker-arch-to-rust-target.sh "${TARGETPLATFORM}"` --toolchain "${RUSTC_VERSION}"

## Run the planner from cargo-chef ##
FROM --platform=${BUILDPLATFORM} chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

## Actual build stage ##
FROM --platform=${BUILDPLATFORM} chef AS builder 

ARG TARGETPLATFORM

# Build dependencies
COPY --from=planner /app/recipe.json recipe.json
RUN cargo chef cook \
  --release \
  --recipe-path recipe.json \
  --target $(/docker-arch-to-rust-target.sh "${TARGETPLATFORM}")

# Build the rest
COPY . .
RUN cargo build \
  --release \
  --bin mas-cli \
  --target $(/docker-arch-to-rust-target.sh "${TARGETPLATFORM}")
# Move the binary to avoid having to guess its name in the next stage
#
RUN mv target/$(/docker-arch-to-rust-target.sh "${TARGETPLATFORM}")/release/mas-cli /mas-cli

## Runtime stage ##
FROM --platform=${TARGETPLATFORM} gcr.io/distroless/cc
COPY --from=builder /mas-cli /mas-cli
ENTRYPOINT ["/mas-cli"]
