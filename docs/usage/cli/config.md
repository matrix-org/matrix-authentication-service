# `config`

Helps dealing with the configuration

## `config check`

Check the validity of configuration files.

```console
$ mas-cli config check --config=config.yaml
INFO mas_cli::config: Configuration file looks good path=["config.yaml"]
```

## `config dump`

Dump the merged configuration tree.

```console
$ mas-cli config dump --config=first.yaml --config=second.yaml
---
oauth2:
  # ...
```

## `config generate`

Generate a sample configuration file.
It generates random signing keys (`.oauth2.keys`) and the cookie encryption secret (`.cookies.secret`).

```console
$ mas-cli config generate > config.yaml
INFO generate: mas_config::oauth2: Generating keys...
INFO generate:rsa: mas_config::oauth2: Done generating RSA key
INFO generate:ecdsa: mas_config::oauth2: Done generating ECDSA key
```
