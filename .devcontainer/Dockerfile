FROM mcr.microsoft.com/vscode/devcontainers/rust:0-1

RUN apt-get update && export DEBIAN_FRONTEND=noninteractive \
     && apt-get -y install --no-install-recommends postgresql-client

COPY .env /.env

# TODO: pre-build custom images, those take too much time
#RUN cargo install sqlx-cli --no-default-features --features postgres
#RUN cargo install cargo-edit