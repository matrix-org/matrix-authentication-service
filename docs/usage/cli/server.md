# `server`

Runs the authentication service.

```
$ mas-cli server
INFO mas_cli::server: Starting task scheduler
INFO mas_core::templates: Loading builtin templates
INFO mas_cli::server: Listening on http://0.0.0.0:8080
```

A `--migrate` flag can be set to automatically run pending database migrations on startup.
