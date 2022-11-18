# OAuth 2.0 authentication server for Matrix

This is an attempt to implement an OAuth 2.0 and OpenID Connect authentication server for Matrix, following [MSC2964](https://github.com/matrix-org/matrix-doc/pull/2964).
Don't expect too much here for now, this is very much a work in progress.

See the [Documentation](https://matrix-org.github.io/matrix-authentication-service/index.html) for information on installation and use.

## Running

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
- Run the database migrations via `cargo run -- database migrate`
- Run the server via `cargo run -- server -c config.yaml`
- Go to <http://localhost:8080/>
