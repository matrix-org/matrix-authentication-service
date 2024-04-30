# Configuration file reference

## `http`

Controls the web server.

```yaml
http:
  # Public URL base used when building absolute public URLs
  public_base: https://auth.example.com/

  # OIDC issuer advertised by the service. Defaults to `public_base`
  issuer: https://example.com/

  # List of HTTP listeners, see below
  listeners:
    # ...
```

### `http.listeners`

Each listener can serve multiple resources, and listen on multiple TCP ports or UNIX sockets.

```yaml
http:
  listeners:
    # The name of the listener, used in logs and metrics
    - name: web

      # List of resources to serve
      resources:
        # Serves the .well-known/openid-configuration document
        - name: discovery
        # Serves the human-facing pages, such as the login page
        - name: human
        # Serves the OAuth 2.0/OIDC endpoints
        - name: oauth
        # Serves the Matrix C-S API compatibility endpoints
        - name: compat
        # Serve the GraphQL API used by the frontend,
        # and optionally the GraphQL playground
        - name: graphql
          playground: true
        # Serve the given folder on the /assets/ path
        - name: assets
          path: ./share/assets/

      # List of addresses and ports to listen to
      binds:
        # First option: listen to the given address
        - address: "[::]:8080"

        # Second option: listen on the given host and port combination
        - host: localhost
          port: 8081

        # Third option: listen on the given UNIX socket
        - socket: /tmp/mas.sock

        # Fourth option: grab an already open file descriptor given by the parent process
        # This is useful when using systemd socket activation
        - fd: 1
          # Kind of socket that was passed, defaults to tcp
          kind: tcp # or unix

      # Whether to enable the PROXY protocol on the listener
      proxy_protocol: false

      # If set, makes the listener use TLS with the provided certificate and key
      tls:
        #certificate: <inline PEM>
        certificate_file: /path/to/cert.pem
        #key: <inline PEM>
        key_file: /path/to/key.pem
        #password: <password to decrypt the key>
        #password_file: /path/to/password.txt
```

The following additional resources are available, although it is recommended to serve them on a separate listener, not exposed to the public internet:

- `name: prometheus`: serves a Prometheus-compatible metrics endpoint on `/metrics`, if the Prometheus exporter is enabled in `telemetry.metrics.exporter`.
- `name: health`: serves the health check endpoint on `/health`.

## `database`

Configure how to connect to the PostgreSQL database.

```yaml
database:
  # Full connection string as per
  # https://www.postgresql.org/docs/13/libpq-connect.html#id-1.7.3.8.3.6
  uri: postgresql://user:password@hostname:5432/database?sslmode=require

  # -- OR --
  # Separate parameters
  host: hostname
  port: 5432
  #socket:
  username: user
  password: password
  database: database

  # Additional parameters for the connection pool
  min_connections: 0
  max_connections: 10
  connect_timeout: 30
  idle_timeout: 600
  max_lifetime: 1800
```

## `matrix`

Settings related to the connection to the Matrix homeserver

```yaml
matrix:
  # The homeserver name, as per the `server_name` in the Synapse configuration file
  homeserver: example.com

  # Shared secret used to authenticate the service to the homeserver
  # This must be of high entropy, because leaking this secret would allow anyone to perform admin actions on the homeserver
  secret: "SomeRandomSecret"

  # URL to which the homeserver is accessible from the service
  endpoint: "http://localhost:8008"
```

## `templates`

Allows loading custom templates

```yaml
templates:
  # From where to load the templates
  # This is relative to the current working directory, *not* the config file
  path: /to/templates

  # Path to the frontend assets manifest file
  assets_manifest: /to/manifest.json
```

## `clients`

List of OAuth 2.0/OIDC clients and their keys/secrets. Each `client_id` must be a [ULID](https://github.com/ulid/spec).

```yaml
clients:
  # Confidential client
  - client_id: 000000000000000000000FIRST
    client_auth_method: client_secret_post
    client_secret: secret
    # List of authorized redirect URIs
    redirect_uris:
      - http://localhost:1234/callback
  # Public client
  - client_id: 00000000000000000000SEC0ND
    client_auth_method: none
```

**Note:** any additions or modification in this list are synced with the database on server startup. Removed entries are only removed with the [`config sync --prune`](../reference/cli/config.md#config-sync---prune---dry-run) command.

## `secrets`

Signing and encryption secrets

```yaml
secrets:
  # Encryption secret (used for encrypting cookies and database fields)
  # This must be a 32-byte long hex-encoded key
  encryption: c7e42fb8baba8f228b2e169fdf4c8216dffd5d33ad18bafd8b928c09ca46c718

  # Signing keys
  keys:
    # It needs at least an RSA key to work properly
    - kid: "ahM2bien"
      key: |
        -----BEGIN RSA PRIVATE KEY-----
        MIIEowIBAAKCAQEAuf28zPUp574jDRdX6uN0d7niZCIUpACFo+Po/13FuIGsrpze
        yMX6CYWVPalgXW9FCrhxL+4toJRy5npjkgsLFsknL5/zXbWKFgt69cMwsWJ9Ra57
        bonSlI7SoCuHhtw7j+sAlHAlqTOCAVz6P039Y/AGvO6xbC7f+9XftWlbbDcjKFcb
        pQilkN9qtkdEH7TLayMAFOsgNvBlwF9+oj9w5PIk3veRTdBXI4GlHjhhzqGZKiRp
        oP9HnycHHveyT+C33vuhQso5a3wcUNuvDVOixSqR4kvSt4UVWNK/KmEQmlWU1/m9
        ClIwrs8Q79q0xkGaSa0iuG60nvm7tZez9TFkxwIDAQABAoIBAHA5YkppQ7fJSm0D
        wNDCHeyABNJWng23IuwZAOXVNxB1bjSOAv8yNgS4zaw/Hx5BnW8yi1lYZb+W0x2u
        i5X7g91j0nkyEi5g88kJdFAGTsM5ok0BUwkHsEBjTUPIACanjGjya48lfBP0OGWK
        LJU2Acbjda1aeUPFpPDXw/w6bieEthQwroq3DHCMnk6i9bsxgIOXeN04ij9XBmsH
        KPCP2hAUnZSlx5febYfHK7/W95aJp22qa//eHS8cKQZCJ0+dQuZwLhlGosTFqLUm
        qhPlt/b1EvPPY0cq5rtUc2W31L0YayVEHVOQx1fQIkH2VIUNbAS+bfVy+o6WCRk6
        s1XDhsECgYEA30tykVTN5LncY4eQIww2mW8v1j1EG6ngVShN3GuBTuXXaEOB8Duc
        yT7yJt1ZhmaJwMk4agmZ1/f/ZXBtfLREGVzVvuwqRZ+LHbqIyhi0wQJA0aezPote
        uTQnFn+IveHGtpQNDYGL/UgkexuCxbc2HOZG51JpunCK0TdtVfO/9OUCgYEA1TuS
        2WAXzNudRG3xd/4OgtkLD9AvfSvyjw2LkwqCMb3A5UEqw7vubk/xgnRvqrAgJRWo
        jndgRrRnikHCavDHBO0GAO/kzrFRfw+e+r4jcLl0Yadke8ndCc7VTnx4wQCrMi5H
        7HEeRwaZONoj5PAPyA5X+N/gT0NNDA7KoQT45DsCgYBt+QWa6A5jaNpPNpPZfwlg
        9e60cAYcLcUri6cVOOk9h1tYoW7cdy+XueWfGIMf+1460Z90MfhP8ncZaY6yzUGA
        0EUBO+Tx10q3wIfgKNzU9hwgZZyU4CUtx668mOEqy4iHoVDwZu4gNyiobPsyDzKa
        dxtSkDc8OHNV6RtzKpJOtQKBgFoRGcwbnLH5KYqX7eDDPRnj15pMU2LJx2DJVeU8
        ERY1kl7Dke6vWNzbg6WYzPoJ/unrJhFXNyFmXj213QsSvN3FyD1pFvp/R28mB/7d
        hVa93vzImdb3wxe7d7n5NYBAag9+IP8sIJ/bl6i9619uTxwvgtUqqzKPuOGY9dnh
        oce1AoGBAKZyZc/NVgqV2KgAnnYlcwNn7sRSkM8dcq0/gBMNuSZkfZSuEd4wwUzR
        iFlYp23O2nHWggTkzimuBPtD7Kq4jBey3ZkyGye+sAdmnKkOjNILNbpIZlT6gK3z
        fBaFmJGRJinKA+BJeH79WFpYN6SBZ/c3s5BusAbEU7kE5eInyazP
        -----END RSA PRIVATE KEY-----
    - kid: "iv1aShae"
      key: |
        -----BEGIN EC PRIVATE KEY-----
        MHQCAQEEIE8yeUh111Npqu2e5wXxjC/GA5lbGe0j0KVXqZP12vqioAcGBSuBBAAK
        oUQDQgAESKfUtKaLqCfhK+p3z870W59yOYvd+kjGWe+tK16SmWzZJbRCgdHakHE5
        MC6tJRnvedsYoKTrYoDv/XZIBI9zlA==
        -----END EC PRIVATE KEY-----
```

### `secrets.keys`

The service can use a number of key types for signing.
The following key types are supported:

- RSA
- ECDSA with the P-256 (`prime256v1`) curve
- ECDSA with the P-384 (`secp384r1`) curve
- ECDSA with the K-256 (`secp256k1`) curve

Each entry must have a unique (and arbitrary) `kid`, plus the key itself.
The key can either be specified inline (with the `key` property), or loaded from a file (with the `key_file` property).
The following key formats are supported:

- PKCS#1 PEM or DER-encoded RSA private key
- PKCS#8 PEM or DER-encoded RSA or ECDSA private key, encrypted or not
- SEC1 PEM or DER-encoded ECDSA private key

For PKCS#8 encoded keys, the `password` or `password_file` properties can be used to decrypt the key.

## `passwords`

Settings related to the local password database

```yaml
passwords:
  # Whether to enable the password database.
  # If disabled, users will only be able to log in using upstream OIDC providers
  enabled: true

  # List of password hashing schemes being used
  # /!\ Only change this if you know what you're doing
  # TODO: document this section better
  schemes:
    - version: 1
      algorithm: argon2id
```

## `policy`

Policy settings

```yaml
policy:
  data:
    admin_users:
      - person1
      - person2

    # Dynamic Client Registration
    client_registration:
      # don't require URIs to be on the same host. default: false
      allow_host_mismatch: true
      # allow non-SSL and localhost URIs. default: false
      allow_insecure_uris: true

    # Registration using passwords
    passwords:
      # minimum length of a password. default: ?
      min_length: 8
      # require at least one lowercase character in a password. default: false
      require_lowercase: true
      # require at least one uppercase character in a password. default: false
      require_uppercase: true
      # require at least one number in a password. default: false
      require_number: true
```

## `telemetry`

Settings related to metrics and traces

```yaml
telemetry:
  tracing:
    # List of propagators to use for extracting and injecting trace contexts
    propagators:
      # Propagate according to the W3C Trace Context specification
      - tracecontext
      # Propagate according to the W3C Baggage specification
      - baggage
      # Propagate trace context with Jaeger compatible headers
      - jaeger

    # The default: don't export traces
    exporter: none

    # Export traces to an OTLP-compatible endpoint
    #exporter: otlp
    #endpoint: https://localhost:4318

  metrics:
    # The default: don't export metrics
    exporter: none

    # Export metrics to an OTLP-compatible endpoint
    #exporter: otlp
    #endpoint: https://localhost:4317

    # Export metrics by exposing a Prometheus endpoint
    # This requires mounting the `prometheus` resource to an HTTP listener
    #exporter: prometheus

  sentry:
    # DSN to use for sending errors and crashes to Sentry
    dsn: https://public@host:port/1
```

### `email`

Settings related to sending emails

```yaml
email:
  from: '"The almighty auth service" <auth@example.com>'
  reply_to: '"No reply" <no-reply@example.com>'

  # Default transport: don't send any emails
  transport: blackhole

  # Send emails using SMTP
  #transport: smtp
  #mode: plain | tls | starttls
  #hostname: localhost
  #port: 587
  #username: username
  #password: password

  # Send emails by calling a local sendmail binary
  #transport: sendmail
  #command: /usr/sbin/sendmail

  # Send emails through the AWS SESv2 API
  # This uses the AWS SDK, so the usual AWS environment variables are supported
  #transport: aws_ses
```

### `upstream_oauth2`

Settings related to upstream OAuth 2.0/OIDC providers.
Additions and modifications within this section are synced with the database on server startup.
Removed entries are only removed with the [`config sync --prune`](./cli/config.md#config-sync---prune---dry-run) command.

#### `upstream_oauth2.providers`

A list of upstream OAuth 2.0/OIDC providers to use to authenticate users.

Sample configurations for popular providers can be found in the [upstream provider setup](../setup/sso.md#sample-configurations) guide.

```yaml
upstream_oauth2:
  providers:
    - # A unique identifier for the provider
      # Must be a valid ULID
      id: 01HFVBY12TMNTYTBV8W921M5FA

      # The issuer URL, which will be used to discover the provider's configuration.
      # If discovery is enabled, this *must* exactly match the `issuer` field
      # advertised in `<issuer>/.well-known/openid-configuration`.
      issuer: https://example.com/

      # A human-readable name for the provider,
      # which will be displayed on the login page
      #human_name: Example

      # A brand identifier for the provider, which will be used to display a logo
      # on the login page. Values supported by the default template are:
      #  - `apple`
      #  - `google`
      #  - `facebook`
      #  - `github`
      #  - `gitlab`
      #  - `twitter`
      #brand_name: google

      # The client ID to use to authenticate to the provider
      client_id: mas-fb3f0c09c4c23de4

      # The client secret to use to authenticate to the provider
      # This is only used by the `client_secret_post`, `client_secret_basic`
      # and `client_secret_jwk` authentication methods
      #client_secret: f4f6bb68a0269264877e9cb23b1856ab

      # Which authentication method to use to authenticate to the provider
      # Supported methods are:
      #   - `none`
      #   - `client_secret_basic`
      #   - `client_secret_post`
      #   - `client_secret_jwt`
      #   - `private_key_jwt` (using the keys defined in the `secrets.keys` section)
      token_endpoint_auth_method: client_secret_post

      # What signing algorithm to use to sign the authentication request when using 
      # the `private_key_jwt` or the `client_secret_jwt` authentication methods
      #token_endpoint_auth_signing_alg: RS256

      # The scopes to request from the provider
      # In most cases, it should always include `openid` scope
      scope: "openid email profile"

      # How the provider configuration and endpoints should be discovered
      # Possible values are:
      #  - `oidc`: discover the provider through OIDC discovery,
      #     with strict metadata validation (default)
      #  - `insecure`: discover through OIDC discovery, but skip metadata validation
      #  - `disabled`: don't discover the provider and use the endpoints below
      #discovery_mode: oidc

      # Whether PKCE should be used during the authorization code flow.
      # Possible values are:
      #  - `auto`: use PKCE if the provider supports it (default)
      #    Determined through discovery, and disabled if discovery is disabled
      #  - `always`: always use PKCE (with the S256 method)
      #  - `never`: never use PKCE
      #pkce_method: auto

      # The provider authorization endpoint
      # This takes precedence over the discovery mechanism
      #authorization_endpoint: https://example.com/oauth2/authorize

      # The provider token endpoint
      # This takes precedence over the discovery mechanism
      #token_endpoint: https://example.com/oauth2/token

      # The provider JWKS URI
      # This takes precedence over the discovery mechanism
      #jwks_uri: https://example.com/oauth2/keys

      # How user attributes should be mapped
      #
      # Most of those attributes have two main properties:
      #   - `action`: what to do with the attribute. Possible values are:
      #      - `ignore`: ignore the attribute
      #      - `suggest`: suggest the attribute to the user, but let them opt out
      #      - `force`: always import the attribute, and don't fail if it's missing
      #      - `require`: always import the attribute, and fail if it's missing
      #   - `template`: a Jinja2 template used to generate the value. In this template,
      #      the `user` variable is available, which contains the user's attributes 
      #      retrieved from the `id_token` given by the upstream provider.
      #
      # Each attribute has a default template which follows the well-known OIDC claims.
      #
      claims_imports:
        # The subject is an internal identifier used to link the
        # user's provider identity to local accounts.
        # By default it uses the `sub` claim as per the OIDC spec,
        # which should fit most use cases.
        subject:
          #template: "{{ user.sub }}"

        # The localpart is the local part of the user's Matrix ID.
        # For example, on the `example.com` server, if the localpart is `alice`,
        #  the user's Matrix ID will be `@alice:example.com`.
        localpart:
          #action: force
          #template: "{{ user.preferred_username }}"

        # The display name is the user's display name.
        displayname:
          #action: suggest
          #template: "{{ user.name }}"

        # An email address to import.
        email:
          #action: suggest
          #template: "{{ user.email }}"

          # Whether the email address must be marked as verified.
          # Possible values are:
          #  - `import`: mark the email address as verified if the upstream provider
          #     has marked it as verified, using the `email_verified` claim.
          #     This is the default.
          #   - `always`: mark the email address as verified
          #   - `never`: mark the email address as not verified
          #set_email_verification: import
```
