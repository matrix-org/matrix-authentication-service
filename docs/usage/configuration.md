# Configuration file reference

## `http`

Controls the web server.

```yaml
http:
  listeners:
  - name: web
    resources:
    - name: discovery
    - name: human
    - name: oauth
    - name: compat
    - name: graphql
      playground: true
    - name: assets
      # Path from which to serve static files
      path: ./frontend/dist/
    binds:
    # On what address and port the server should listen to
    - address: '[::]:8080'
    proxy_protocol: false
  - name: internal
    resources:
    - name: health
    binds:
    - host: localhost
      port: 8081
    proxy_protocol: false
  # Public URL base used when building absolute public URLs
  public_base: http://[::]:8080/
  issuer: http://[::]:8080/
```

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
    client_auth_method: clent_secret_post
    client_secret: secret
    # List of authorized redirect URIs
    redirect_uris:
      - http://localhost:1234/callback
  # Public client
  - client_id: 00000000000000000000SEC0ND
    client_auth_method: none
```

## `secrets`

Signing and encryption secrets

```yaml
secrets:
  # Encryption secret (used for encrypting cookies and database fields)
  encryption: c7e42fb8baba8f228b2e169fdf4c8216dffd5d33ad18bafd8b928c09ca46c718

  # Signing keys
  keys:
    # It needs at least an RSA key to work properly
    - kid: "ahM2bien"
      key: |
        -----BEGIN PRIVATE KEY-----
        MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7iinu0NXjWP5/
        /4OqyqOMI5uLJIHSrYIZLUlWMldtXmNy0c/pan+gxvZogiYx0cNydO/FogNbC4oD
        yj7RIF+QcWJ8wcdG94/P+Xs3HFQzIZfwF+78RWQQJ7nQFekXJ1wQSXV4giw9b4XR
        YkoVhHlyxyYGBFffO//DtYVto4uHvXVL0M27bV6l1K8VKspF72gb8Vt44V8OX5hT
        sEsYW8SjOD1neEoVKiY6XP63cAG9FTB4a4sKkcUqwjrKEYKio/JLujmCl96eLN18
        cuqr6XuSDKvuVJtb+ZNLJi61vIOlD8cz3wu37hr3PCUZ+Ko9Ley+QfopJ3WYFxrI
        IjQKb0W5AgMBAAECggEBAK87ZfsTfwczPHn1Ed4gAbkL/GaC8hscrJdBzWiRGUfE
        DkBW82IydJaR0ePM2EtsqKblxLRxsZj8qzTnYNKe4SxiBZh0p/MTlnjJr+vKuJIe
        LY3VjySA4gKGXASmtGlCCa/eM7kqSJQPBIakxHxej+xDULAGluSrd0wy7D2JtvJY
        5By+2apILUujBZZU/iUyB2AqK6IrzALo2gTV9Jhun9Wz0k3DXZBGd41v42BhZ+Rx
        bHHgpuUTyDQOpKqJ5g1kN4qGlN/CeoontxcE5NOSgtipWeQEuelT8t4eZKHTXBS+
        Byd+uFe8oobWRY2crLptX8TZEENH7wX7y2YgNYUbeZECgYEA95YRhDuukcrDiNuF
        fOXs+99XFORsKTbtZYwrouc7PI2CYb0I9ezoQMu3dzWIwOTUQHea5qCo/dYzbeED
        fNzwPb2zaWaWFbkEWVTOwRewL+NfP+Ek2Nml+dVJm3d35qdIHYV+9gAcI87iCHxA
        gqc13ZS4ba+5/vV6OYwNSAeW0TcCgYEAwem1F9zhVVOIReh3JaJLpZn0xuvZs5kN
        TzvFXar33LKdulk5liC3L7ZrqspGESU0JC3pANR8PwuNteEEdHnkC5UTEqMf/fxG
        j5CObJl+e2CiV2CNbe+3IQ1PKSxopD+Sq65ze7aP2moVZg94mbw4dsN+uY5QEql1
        Bmq0b7Wm2I8CgYBOqlDgefIKgqlEF7O/LnLwyFKr4bP4GGqvZC0NMnkg0TmHAoAR
        W3ej9tZROyI7X7mMzjPaaVuoY2Gt3Nu11aFDjL2vlJfFSSb3lzmmInepj43ZBxkl
        CWpyCfG8QuZG1AnWz266jOhj/DzXQ1tf5+72e2Vp/HaVaruuAzDJHRgvWwKBgAHy
        aMEOlKyYpBufk+Kq2HuXKh/9KjhlZv7OqNKh7s8mc/L1BmD9fxlZiYczdLSjXPyo
        AVjiyUSQxyF2WucYejOrkX90Z9PS/ppeZy+r8tsmQzsBWyopZ/tK+Op+6aYMhVp3
        6+zoDlWxDvnxWdKhUyfOGq2eQiuNzAD+fUVJ25z9AoGARUJ4C87X7vH4QnsIE0g+
        ni0xSs8DgSq0v8+cJ7xwyN+NnC6eeU9N2U/m/5anLEM2GFjo4kghLDkC/2urc8dD
        UtiisQjWz3O88QHqOvclEAmveuxfCYr/A/CWGdkH3YoK+AXIj3fkwb2Qd//rJ9zL
        dT3XPCRatoVKLNKzUGNVcFM=
        -----END PRIVATE KEY-----
    - kid: "iv1aShae"
      key: |
        -----BEGIN PRIVATE KEY-----
        MIGEAgEAMBAGByqGSM49AgEGBSuBBAAKBG0wawIBAQQgaa7KvLdq72Nb7i7pGm/6
        SCW0RAKFcVwz7P9/8Wo2TTShRANCAATlTf0uyezm7riXjZdn1XND00uf4d1tc1jc
        V4CiFiDQsDX+3znAGxqhTuoOkVn/G5lwgE1cgTX57r9cyYkso9UY
        -----END PRIVATE KEY-----
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
