# Architecture

The service is meant to be easily embeddable, with only a dependency to a database.
It is also meant to stay lightweight in terms of resource usage and easily scalable horizontally.

## Workspace and crate split

The whole repository is a [Cargo Workspace](https://doc.rust-lang.org/book/ch14-03-cargo-workspaces.html) that includes multiple crates under the `/crates` directory.

This includes:

 - `mas-cli`: Command line utility, main entry point
 - `mas-config`: Configuration parsing and loading
 - `mas-data-model`: Models of objects that live in the database, regardless of the storage backend
 - `mas-email`: High-level email sending abstraction
 - `mas-handlers`: Main HTTP application logic
 - `mas-iana`: Auto-generated enums from IANA registries
 - `mas-iana-codegen`: Code generator for the `mas-iana` crate
 - `mas-jose`: JWT/JWS/JWE/JWK abstraction
 - `mas-static-files`: Frontend static files (CSS/JS). Includes some frontend tooling
 - `mas-storage`: Interactions with the database
 - `mas-tasks`: Asynchronous task runner and scheduler
 - `mas-warp-utils`: Various filters and utilities for the `warp` web framework
 - `oauth2-types`: Useful structures and types to deal with OAuth 2.0/OpenID Connect endpoints. This might end up published as a standalone library as it can be useful in other contexts.

## Important crates

The project makes use of a few important crates.

### Async runtime: `tokio`

[Tokio](https://tokio.rs/) is the async runtime used by the project.
The choice of runtime does not have much impact on most of the code.

It has an impact when:

 - spawning asynchronous work (as in "not awaiting on it immediately")
 - running CPU-intensive tasks. They should be ran in a blocking context using `tokio::task::spawn_blocking`. This includes password hashing and other crypto operations.
 - when dealing with shared memory, e.g. mutexes, rwlocks, etc.

### Logging: `tracing`

Logging is handled through the [`tracing`](https://docs.rs/tracing/*/tracing/) crate.
It provides a way to emit structured log messages at various levels.

```rust
use tracing::{info, debug};

info!("Logging some things");
debug!(user = "john", "Structured stuff");
```

`tracing` also provides ways to create spans to better understand where a logging message comes from.
In the future, it will help building OpenTelemetry-compatible distributed traces to help with debugging.

`tracing` is becoming the standard to log things in Rust.
By itself it will do nothing unless a subscriber is installed to -for example- log the events to the console.

The CLI installs [`tracing-subcriber`](https://docs.rs/tracing-subscriber/*/tracing_subscriber/) on startup to log in the console.
It looks for a `RUST_LOG` environment variable to determine what event should be logged.

### Error management: `thiserror` / `anyhow`

[`thiserror`](https://docs.rs/thiserror/*/thiserror/) helps defining custom error types.
This is especially useful for errors that should be handled in a specific way, while being able to augment underlying errors with additional context.

[`anyhow`](https://docs.rs/anyhow/*/anyhow/) helps dealing with chains of errors.
It allows for quickly adding additional context around an error while it is being propagated.

Both crates work well together and complement each other.

### Database interactions: `sqlx`

Interactions with the database are done through [`sqlx`](https://github.com/launchbadge/sqlx), an async, pure-Rust SQL library with compile-time check of queries.
It also handles schema migrations.

### Web framework: `warp`

[`warp`](https://docs.rs/warp/*/warp/) is an easy, macro-free web framework.
Its composability makes a lot of sense when implementing OAuth 2.0 endpoints, because of the need to deal with a lot of different scenarios.

### Templates: `tera`

[Tera](https://tera.netlify.app/) was chosen as template engine for its simplicity as well as its ability to load templates at runtime.
The builtin templates are embedded in the final binary through some macro magic.

The downside of Tera compared to compile-time template engines is the possibility of runtime crashes.
This can however be somewhat mitigated with unit tests.

### Crates from *RustCrypto*

The [RustCrypto team](https://github.com/RustCrypto) offer high quality, independent crates for dealing with cryptography.
The whole project is highly modular and APIs are coherent between crates.
