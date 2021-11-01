ARG RUSTC_VERSION=1.56.0

# cargo-chef helps with caching dependencies between builds
FROM docker.io/library/rust:${RUSTC_VERSION}-slim AS chef
WORKDIR /app
RUN cargo install --locked cargo-chef

FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder 
COPY --from=planner /app/recipe.json recipe.json
# Build dependencies
RUN cargo chef cook --release --recipe-path recipe.json
# Build the rest
COPY . .
RUN cargo build --release --bin mas-cli

FROM gcr.io/distroless/cc
COPY --from=builder /app/target/release/mas-cli /mas-cli
ENTRYPOINT ["/mas-cli"]
