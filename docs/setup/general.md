# General configuration

## Initial configuration generation

The service needs a few unique secrets and keys to work.
It mainly includes:

 - the various signing keys referenced in the [`secrets.keys`](../usage/configuration.md#secrets) section
 - the encryption key used to encrypt fields in the database and cookies, set in the [`secrets.encryption`](../usage/configuration.md#secrets) section
 - a shared secret between the service and the homeserver, set in the [`matrix.secret`](../usage/configuration.md#matrix) section

Although it is possible to generate these secrets manually, it is strongly recommended to use the [`config generate`](../usage/cli/config.md#config-generate) command to generate a configuration file with unique secrets and keys.

```sh
mas-cli config generate > config.yaml
```

If you're using the docker container, the command `mas-cli` can be invoked with `docker run`:

```sh
docker run ghcr.io/matrix-org/matrix-authentication-service:main config generate > config.yaml
```

**Note:** The generated configuration file is very extensive, and contains the default values for all the configuration options.
This will be made easier to read in the future, but in the meantime, it is recommended to strip untouched options from the configuration file.

## Using and inspecting the configuration file

When using the `mas-cli`, multiple configuration files can be loaded, with the following rule:

1. If the `--config` option is specified, possibly multiple times, load the file at the specified path, relative to the current working directory
2. If not, load the files specified in the `MAS_CONFIG` environment variable if set, separated by `:`, relative to the current working directory
3. If not, load the file at `config.yaml` in the current working directory

The validity of the configuration file can be checked using the [`config check`](../usage/cli/config.md#config-check) command:

```sh
# This will read both the `first.yaml` and `second.yaml` files
mas-cli config check --config=first.yaml --config=second.yaml

# This will also read both the `first.yaml` and `second.yaml` files
MAS_CONFIG=first.yaml:second.yaml mas-cli config check

# This will only read the `config.yaml` file
mas-cli config check
```

To help understand what the resulting configuration looks like after merging all the configuration files, the [`config dump`](../usage/cli/config.md#config-dump) command can be used:

```sh
mas-cli config dump
```

## Configuration schema

The configuration file is validated against a JSON schema, which can be found [here](../config.schema.json).
Many [tools in text editors](https://json-schema.org/implementations.html#editors) can use this schema to provide autocompletion and validation.

## Syncing the configuration file with the database

Some sections of the configuration file need to be synced every time the configuration file is updated.
This includes the [`clients`](../usage/configuration.md#clients) and [`upstream_oauth`](../usage/configuration.md#upstream-oauth) sections.
Once the database is initialized, the [`config sync`](../usage/cli/config.md#config-sync---prune---dry-run) command can be used to sync the configuration file with the database:

```sh
mas-cli config sync
```

By default, this will only add new clients and upstream OAuth providers, and will not remove entries that were removed from the configuration file.
To do so, use the `--purge` option:

```sh
mas-cli config sync --purge
```

Before synchronizing the configuration file, it is *recommended* to do it in with the `--dry-run` option to see what will be changed, without committing the changes to the database:

```sh
mas-cli config sync --dry-run
# with the --purge option
mas-cli config sync --dry-run --purge
```

## Next step

After generating the configuration file, the next step is to [set up a database](./database.md).
