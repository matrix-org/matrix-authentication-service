# Installation

## Requirements

 - A PostgreSQL database
 - Either:
   - A [Rust and Cargo toolchain](https://www.rust-lang.org/learn/get-started) (recommended for development),
   - [Node.js and npm](https://nodejs.org/) and
   - [Open Policy Agent](https://www.openpolicyagent.org/docs/latest/#1-download-opa)
 - **or** [Docker](https://www.docker.com/get-started) (or a compatible container runtime)

## Installing from the source

1. Get the source
   ```sh
   git clone https://github.com/matrix-org/matrix-authentication-service.git
   cd matrix-authentication-service
   ```
1. Build the frontend
   ```sh
   cd frontend
   npm ci
   npm run build
   cd ..
   ```
1. Build the Open Policy Agent policies
   ```sh
   cd policies
   make
   cd ..
   ```
   OR, if you don't have `opa` installed and want to build through the OPA docker image
   ```sh
   cd policies
   make DOCKER=1
   cd ..
   ```
1. Compile the CLI
   ```sh
   cargo build --release
   ```
1. Grab the built binary
   ```sh
   cp ./target/release/mas-cli ~/.local/bin # Copy the binary somewhere in $PATH
   mas-cli --help # Should display the help message
   ```

## Running from the Docker image

A Docker image is available here: [`ghcr.io/matrix-org/matrix-authentication-service:main`](https://ghcr.io/matrix-org/matrix-authentication-service:main)

---

```sh
docker run --rm ghcr.io/matrix-org/matrix-authentication-service:main --help
```
```
mas-cli

USAGE:
    mas-cli [OPTIONS] [SUBCOMMAND]

FLAGS:
    -h, --help       Print help information
    -V, --version    Print version information

OPTIONS:
    -c, --config <CONFIG>...    Path to the configuration file [default: config.yaml]

SUBCOMMANDS:
    config       Configuration-related commands
    database     Manage the database
    help         Print this message or the help of the given subcommand(s)
    manage       Manage the instance
    server       Runs the web server
    templates    Templates-related commands
```

Note that when running in a Docker environment

---

The next step is to generate the configuration file and tweak it to reach the PostgreSQL database.

## Database

You can run a PostgreSQL database locally via docker.
```sh
docker run -p 5432:5432 -e 'POSTGRES_USER=postgres' -e 'POSTGRES_PASSWORD=postgres' -e 'POSTGRES_DATABASE=postgres' postgres
```

Or if you uses your own shared database server you can previously create the database.

Assuming your PostgreSQL database user is called `postgres`, first authenticate as the database user with:

```sh
su - postgres
# Or, if your system uses sudo to get administrative rights
sudo -u postgres bash
```

Then, create a postgres user and a database with:
```
# this will prompt for a password for the new user
createuser --pwprompt matrix_authentication_user

createdb --owner=matrix_authentication_user matrix_authentication
```
