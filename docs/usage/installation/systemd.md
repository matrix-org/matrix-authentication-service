# Setup Matrix Authentication Service with Systemd

This is a setup for managing matrix-authentication-service with a user
contributed systemd unit file. It provides a `matrix-authentication-service`
systemd unit file that should be tailored to accommodate your installation
in accordance with the installation instructions provided in
[installation instructions](../installation.md).

## Setup

1. Under the service section, ensure the `User` variable matches which user
you installed matrix-authentication-service under and wish to run it as.
1. Under the service section, ensure the `WorkingDirectory` variable matches
where you have installed matrix-authentication-service.
1. Under the service section, ensure the `ExecStart` variable matches the
appropriate locations of your installation.
1. Copy the `matrix-authentication-service.service` to `/etc/systemd/system/`
1. Reload systemd daemon to tell systemd to load the new unit files
`sudo systemctl daemon-reload`
1. Start Matrix Authentication Service: `sudo systemctl start matrix-authentication-service`
1. Verify Matrix Authentication Service is running:
`sudo systemctl status matrix-authentication-service`
1. *optional* Enable Matrix Authentication Service to start at system boot:
`sudo systemctl enable matrix-authentication-service`

## `matrix-authentication-service.service` file

```
{{#include matrix-authentication-service.service}}
```
