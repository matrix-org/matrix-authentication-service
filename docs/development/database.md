# Database

Interactions with the database goes through `sqlx`.
It provides async database operations with connection pooling, migrations support and compile-time check of queries through macros.

## Compile-time check of queries

To be able to check queries, `sqlx` has to introspect the live database.
Usually it does so by having the database available at compile time, but to avoid that we're using the `offline` feature of `sqlx`, which saves the introspection informatons as a flat file in the repository.

Preparing this flat file is done through `sqlx-cli`, and should be done everytime the database schema or the queries changed.

```sh
# Install the CLI
cargo install sqlx-cli --no-default-features --features postgres

cd crates/storage/ # Must be in the mas-storage crate folder
export DATABASE_URL=postgresql:///matrix_auth
cargo sqlx prepare
```

## Migrations

Migration files live in the `migrations` folder in the `mas-core` crate.

```sh
cd crates/storage/ # Again, in the mas-storage crate folder
export DATABASE_URL=postgresql:///matrix_auth
cargo sqlx migrate run # Run pending migrations
cargo sqlx migrate revert # Revert the last migration
cargo sqlx migrate add -r [description] # Add new migration files
```

Note that migrations are embedded in the final binary and can be run from the service CLI tool.

## Writing database interactions

A typical interaction with the database look like this:

```rust
pub async fn lookup_session(
    executor: impl Executor<'_, Database = Postgres>,
    id: i64,
) -> anyhow::Result<SessionInfo> {
    sqlx::query_as!(
        SessionInfo, // Struct that will be filled with the result
        r#"
            SELECT
                s.id,
                u.id as user_id,
                u.username,
                s.active,
                s.created_at,
                a.created_at as "last_authd_at?"
            FROM user_sessions s
            INNER JOIN users u 
                ON s.user_id = u.id
            LEFT JOIN user_session_authentications a
                ON a.session_id = s.id
            WHERE s.id = $1
            ORDER BY a.created_at DESC
            LIMIT 1
        "#,
        id, // Query parameter
    )
    .fetch_one(executor)
    .await
    // Providing some context when there is an error
    .context("could not fetch session")
}
```

Note that we pass an `impl Executor` as parameter here.
This allows us to use this function from either a simple connection or from an active transaction.

The caveat here is that the `executor` can be used only once, so if an interaction needs to do multiple queries, it should probably take an `impl Acquire` to then acquire a transaction and do multiple interactions.

```rust
pub async fn login(
    conn: impl Acquire<'_, Database = Postgres>,
    username: &str,
    password: String,
) -> Result<SessionInfo, LoginError> {
    let mut txn = conn.begin().await.context("could not start transaction")?;
    // First interaction
    let user = lookup_user_by_username(&mut txn, username)?;
    // Second interaction
    let mut session = start_session(&mut txn, user).await?;
    // Third interaction
    session.last_authd_at = 
        Some(authenticate_session(&mut txn, session.id, password).await?);
    // Commit the transaction once everything went fine
    txn.commit().await.context("could not commit transaction")?;
    Ok(session)
}
```
