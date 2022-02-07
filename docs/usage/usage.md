# Using the service

## Running

Once the configuration is done, one should run the database migrations by running

```sh
mas-cli database migrate
```

The server can then be started by running

```sh
mas-cli server
```

```
Sep 24 14:42:42.743  INFO mas_cli::server: Starting task scheduler
Sep 24 14:42:42.743  INFO mas_core::templates: Loading builtin templates
Sep 24 14:42:42.752  INFO mas_cli::server: Listening on http://0.0.0.0:8080
```

The server should now be accessible through <http://localhost:8080/>.

**Note**: when running with Docker, the port used by the server should be exposed with the `-p` flag:

```sh
docker run --rm \
  -v `pwd`/config.yaml:/config.yaml \
  -p 8080:8080 \
  ghcr.io/matrix-org/matrix-authentication-service:main \
  server
```

## Registering, logging in and out

Through the interface, users are able to create an account by clicking the `Register` button on the top right (or going to [`/register`](http://localhost:8080/register).
They can then end their session by clicking the `Log out` button and log back in.

## Playing around with the playground

The OpenID Foundation hosts a OpenID Connect Playground where one can test logging in through an OIDC provider: https://openidconnect.net/

### Step 1: Add the client to the server config

Add the following section to the server configuration file `config.yaml`:

```yaml
clients:
  - client_id: oidc-playground
    client_secret: verysecret
    redirect_uris:
      - "https://openidconnect.net/callback"
```

### Step 2: Change the playground configuration

 - Navigate to [the playground](https://openidconnect.net/)
 - Click on "Configuration"
 - Server template: *Custom*
 - Paste the discovery document URL found on the service homepage (e.g. `http://localhost:8080/.well-known/openid-configuration`)
 - Click "Use discovery document" ; it should fill out the authorization, token and token keys endpoints
 - Set the OIDC Client ID to `oidc-playground` and the Client Secret to `verysecret` (must match the ones in the configuration)
 - Click "Save"

### Step 3: Run the OpenID Connect flow

Start the flow by clicking the "Start" button.
It should redirect the browser to the authentication service.
If a user is already logged in, it should redirect back to the playground immediately.

Follow the flow to see the code exchange happen.
Note that the last step only works if the service is accessible through the internet.
