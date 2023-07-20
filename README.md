# OAuth 2.0 authentication server for Matrix

This is an attempt to implement an OAuth 2.0 and OpenID Connect authentication server for Matrix, following [MSC2964](https://github.com/matrix-org/matrix-doc/pull/2964).
Don't expect too much here for now, this is very much a work in progress.

See the [Documentation](https://matrix-org.github.io/matrix-authentication-service/index.html) for information on installation and use.

## Running

- [Observe and install requirements](https://matrix-org.github.io/matrix-authentication-service/usage/installation.html#requirements)
- [Install Matrix Authentication Service](https://matrix-org.github.io/matrix-authentication-service/usage/installation.html#installing-from-the-source)
- [Generate the sample config](https://matrix-org.github.io/matrix-authentication-service/usage/configuration.html)
- [Provide the database](https://matrix-org.github.io/matrix-authentication-service/usage/installation.html#database)
- [Customize your minimal configuration](https://matrix-org.github.io/matrix-authentication-service/usage/configuration.html#minimal-configuration)
  - `database.uri`
- [Run the database migrations](https://matrix-org.github.io/matrix-authentication-service/usage/usage.html#running)
- [Run the server](https://matrix-org.github.io/matrix-authentication-service/usage/usage.html#running)
- Go to <http://localhost:8080/>

- Or use the [docker image](https://matrix-org.github.io/matrix-authentication-service/usage/installation.html#running-from-the-docker-image) alternatively.
