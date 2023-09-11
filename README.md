# OAuth2.0 + OpenID Provider for Matrix Homeservers

MAS (Matrix Authentication Service) is an OAuth 2.0 and OpenID Provider server for Matrix.

It has been created to support the migration of Matrix to an OpenID Connect based architecture as per [MSC3861](https://github.com/matrix-org/matrix-doc/pull/3861).

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
- Run a PostgreSQL database locally
  ```sh
  docker run -p 5432:5432 -e 'POSTGRES_USER=postgres' -e 'POSTGRES_PASSWORD=postgres' -e 'POSTGRES_DATABASE=postgres' postgres
  ```
- Update the database URI in `config.yaml` to `postgresql://postgres:postgres@localhost/postgres`
- Run the database migrations via `cargo run -- database migrate`
- Run the server via `cargo run -- server -c config.yaml`
- Go to <http://localhost:8080/>
