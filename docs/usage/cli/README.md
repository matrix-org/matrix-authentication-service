# Command line tool

The command line interface provides subcommands that helps running the service.

## Logging

The overall log level of the CLI can be changed via the `RUST_LOG` environment variable.
Default log level is `info`.
Valid levels from least to most verbose are `error`, `warn`, `info`, `debug` and `trace`.

## Global flags

### `--config`

Sets the configuration file to load.
It can be repeated multiple times to merge multiple files together.

---

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
