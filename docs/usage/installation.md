# Installation

## Requirements

 - A PostgreSQL database
 - Either:
   - A [Rust toolchain](https://www.rust-lang.org/learn/get-started) (recommended for development)
   - or [Docker](https://www.docker.com/get-started) (or a compatible container runtime)

## Installing from the source

1. Get the source
   ```sh
   git clone https://github.com/matrix-org/matrix-authentication-service.git
   cd matrix-authentication-service
   ```
2. Compile the CLI
   ```
   cargo build --release
   ```
3. Grab the built binary
   ```
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
