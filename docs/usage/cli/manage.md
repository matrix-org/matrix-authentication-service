# `manage`

Includes admin-related subcommands.

## `manage register <username> <password>`

Register a new user

```console
$ mas-cli manage register johndoe hunter2
INFO mas_cli::manage: User registered user=User { id: 2, username: "johndoe" }
```

## `manage verify-email <username> <email>`

Mark a user email address as verified
