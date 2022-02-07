# `warp`

**Warning: this document is not up to date**

Warp has a pretty unique approach in terms of routing.
It does not have a central router, rather a chain of filters composed together.

It encourages writing reusable filters to handle stuff like authentication, extracting user sessions, starting database transactions, etc.

Everything related to `warp` currently lives in the `mas-core` crate:

- `crates/core/src/`
  - `handlers/`: The actual handlers for each route
      - `oauth2/`: Everything related to OAuth 2.0/OIDC endpoints
      - `views/`: HTML views (login, registration, account management, etc.)
  - `filters/`: Reusable, composable filters
  - `reply/`: Composable replies

## Defining a new endpoint

We usually keep one endpoint per file and use module roots to combine the filters of endpoints.

This is how it looks like in the current hierarchy at time of writing:
 - `mod.rs`: combines the filters from `oauth2`, `views` and `health`
 - `oauth2/`
     - `mod.rs`: combines filters from `authorization`, `discovery`, etc.
     - `authorization.rs`: handles `GET /oauth2/authorize` and `GET /oauth2/authorize/step`
     - `discovery.rs`: handles `GET /.well-known/openid-configuration`
     - ...
 - `views/`
    - `mod.rs`: combines the filters from `index`, `login`, `logout`, etc.
    - `index.rs`: handles `GET /`
    - `login.rs`: handles `GET /login` and `POST /login`
    - `logout.rs`: handles `POST /logout`
    - ...
 - `health.rs`: handles `GET /health`

All filters are functions that take their dependencies (the database connection pool, the template engine, etc.) as parameters and return an `impl warp::Filter<Extract = (impl warp::Reply,)>`.

```rust
// crates/core/src/handlers/hello.rs

// Don't be scared by the type at the end, just copy-paste it
pub(super) fn filter(
    pool: &PgPool,
    templates: &Templates,
    cookies_config: &CookiesConfig,
) -> impl Filter<Extract = (impl Reply,), Error = Rejection> + Clone + Send + Sync + 'static {
    // Handles `GET /hello/:param`
    warp::path!("hello" / String)
        .and(warp::get())
        // Pass the template engine
        .and(with_templates(templates))
        // Extract the current user session
        .and(optional_session(pool, cookies_config))
        .and_then(get)
}

async fn get(
    // Parameter from the route
    parameter: String,
    // Template engine
    templates: Templates,
    // The current user session
    session: Option<SessionInfo>,
) -> Result<impl Reply, Rejection> {
    let ctx = SomeTemplateContext::new(parameter)
        .maybe_with_session(session);

    let content = templates.render_something(&ctx)?;
    let reply = html(content);
    Ok(reply)
}
```

And then, it can be attached to the root handler:

```rust
// crates/core/src/handlers/mod.rs

use self::{health::filter as health, oauth2::filter as oauth2, hello::filter as hello};

pub fn root(
    pool: &PgPool,
    templates: &Templates,
    config: &RootConfig,
) -> impl Filter<Extract = (impl Reply,), Error = Rejection> + Clone + Send + Sync + 'static {
    health(pool)
        .or(oauth2(pool, templates, &config.oauth2, &config.cookies))
        // Attach it here, passing the right dependencies
        .or(hello(pool, templates, &config.cookies))
}
```
