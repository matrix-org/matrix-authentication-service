# Running the service

To fully function, the service needs to run two main components:

 - An HTTP server
 - A background worker

By default, the [`mas-cli server`](../usage/cli/server.md) command will start both components.
It is possible to only run the HTTP server by setting the `--no-worker` option, and run a background worker with the [`mas-cli worker`](../usage/cli/worker.md) command.

Both components are stateless, and can be scaled horizontally by running multiple instances of each.

## Runtime requirements

Other than the binary, the service needs a few files to run:

 - The templates, referenced by the [`templates.path`](../usage/configuration.md#templates) configuration option
 - The compiled policy, referenced by the [`policy.path`](../usage/configuration.md#policy) configuration option
 - The frontend assets, referenced by the `path` option of the `assets` resource in the [`http.listeners`](../usage/configuration.md#http) configuration section
 - The frontend manifest file, referenced by tge [`templates.assets_manifest`](../usage/configuration.md#templates) configuration option

Be sure to check the [installation instructions](./installation.md) for more information on how to get these files, and make sure the configuration file is updated accordingly.

TODO: systemd service, docker, etc.