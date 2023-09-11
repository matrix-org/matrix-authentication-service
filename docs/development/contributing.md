# Contributing

This document aims to get you started with contributing to the Matrix Authentication Service!

# 1. Who can contribute to MAS?

Everyone is welcome to contribute code to [matrix.org projects](https://github.com/matrix-org), provided that they are willing to license their contributions under the same license as the project itself. We follow a simple 'inbound=outbound' model for contributions: the act of submitting an 'inbound' contribution means that the contributor agrees to license the code under the same terms as the project's overall 'outbound' license - in our case, this is almost always Apache Software License v2 (see [LICENSE](https://github.com/matrix-org/matrix-authentication-service/blob/main/LICENSE)).

# 2. What do I need?

To get MAS running locally from source you will need:

- [Install Rust and Cargo](https://www.rust-lang.org/learn/get-started)
- [Install Node.js and npm](https://nodejs.org/)
- [Install Open Policy Agent](https://www.openpolicyagent.org/docs/latest/#1-download-opa)
- Clone this repository
- Build the frontend
  ```sh
  cd frontend
  npm ci
  npm run build
  cd ..
  ```
- Build the Open Policy Agent policies
  ```sh
  cd policies
  make
  # OR, if you don't have `opa` installed and want to build through the OPA docker image
  make DOCKER=1
  cd ..
  ```
- Generate the sample config via `cargo run -- config generate > config.yaml`
- Run a PostgreSQL database locally
  ```sh
  docker run -p 5432:5432 -e 'POSTGRES_USER=postgres' -e 'POSTGRES_PASSWORD=postgres' -e 'POSTGRES_DATABASE=postgres' postgres
  ```
- Update the database URI in `config.yaml` to `postgresql://postgres:postgres@localhost/postgres`
- Run the database migrations via `cargo run -- database migrate`
- Run the server via `cargo run -- server -c config.yaml`
- Go to <http://localhost:8080/>
