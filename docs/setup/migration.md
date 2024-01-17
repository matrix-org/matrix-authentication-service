# Migrating an existing homeserver

One of the design goals of MAS has been to allow it to be used to migrate an existing homeserver to an OIDC-based architecture.

Specifically without requiring users to re-authenticate and that non-OIDC clients continue to work.

Features that are provided to support this include:

- Ability to import existing password hashes from Synapse
- Ability to import existing sessions and devices
- Ability to import existing access tokens
- Ability to import existing upstream IdP subject ID mappings
- Provides a compatibility layer for legacy Matrix authentication

If
There will be tools to help with the migration process itself. But these aren't quite ready yet.

## Preparing for the migration

The deployment is non-trivial so it is important to read through and understand the steps involved and make a plan before starting.

### Run the migration advisor

You can use the advisor mode of the `syn2mas` tool to identify extra configuration steps or issues with the configuration of the homeserver.

```sh
syn2mas --command=advisor --synapseConfigFile=homeserver.yaml
```

This will output `WARN` entries for any identified actions and `ERROR` entries in the case of any issues that will prevent the migration from working.

### Install and configure MAS alongside your existing homeserver

Follow the instructions in the [installation guide](installation.md) to install MAS alongside your existing homeserver.

### Map any upstream SSO providers

If you are using an upstream SSO provider then you will need to provision the upstream provide in MAS manually.

Each upstream provider will need to be given as an `--upstreamProviderMapping` command line option to the import tool.

### Do a dry-run of the import to test

```sh
syn2mas --command migrate --synapseConfigFile homeserver.yaml --masConfigFile config.yaml --dryRun
```

If no errors are reported then you can proceed to the next step.

## Doing the migration

Having done the preparation, you can now proceed with the actual migration. Note that this will require downtime for the homeserver and is not easily reversible.

### Backup your data

As with any migration, it is important to backup your data before proceeding.

### Shutdown the homeserver

This is to ensure that no new sessions are created whilst the migration is in progress.

### Configure the homeserver

Follow the instructions in the [homeserver configuration guide](homeserver.md) to configure the homeserver to use MAS.

### Do the import

Run `syn2mas` in non-dry-run mode.

```sh
syn2mas --command migrate --synapseConfigFile homeserver.yaml --masConfigFile config.yaml --dryRun false
```

### Start up the homeserver

Start up the homeserver again with the new configuration.

### Update or serve the .well-known

The `.well-known/matrix/client` needs to be served as described [here](./well-known.md).
