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
        - address: '[::]:8080'

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

 - `name: prometheus`: serves the a Prometheus-compatible metrics endpoint on `/metrics`, if the Prometheus exporter is enabled in `telemetry.metrics.exporter`.
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

**Note:** this list is not used at runtime, and any modification of this list must be synced to the database using the [`config sync`](../usage/cli/config.md#config-sync---prune---dry-run) command.

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
      # Propagate trace context with Zipkin compatible headers (single `b3` header variant)
      - b3
      # Propagate trace context with Zipkin compatible headers (multiple `x-b3-*` headers variant)
      - b3multi

    # The default: don't export traces
    exporter: none

    # Export traces to an OTLP-compatible endpoint
    #exporter: otlp
    #endpoint: https://localhost:4317
    
    # Export traces to a Jaeger endpoint
    #exporter: jaeger
    #protocol: http/thrift.binary | udp/thrift.compact
    #endpoint: http://localhost:14268/api/traces # for http/thrift.binary
    #username: username # for http/thrift.binary
    #password: password # for http/thrift.binary
    #agent_host: localhost # for udp/thrift.compact
    #agent_port: 6831 # for udp/thrift.compact

    # Export traces to a Zipkin endpoint
    #exporter: zipkin
    #collector_endpoint: http://localhost:9411/api/v2/spans

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
