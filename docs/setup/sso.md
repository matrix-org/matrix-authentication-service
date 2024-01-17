# Configure an upstream SSO provider

The authentication service supports using an upstream OpenID Connect provider to authenticate its users.
Multiple providers can be configured, and can be used in conjunction with the local password database authentication.

Any OIDC compliant provider should work with the service as long as it supports the authorization code flow.

**Note that the service does not support other SSO protocols such as SAML**, and there is no plan to support them in the future.
A deployment which requires SAML or LDAP-based authentication should use a service like [Dex](https://github.com/dexidp/dex) to bridge between the SAML provider and the authentication service.

## General configuration

Configuration of upstream providers is done in the `upstream_oauth2` section of the configuration file, which has a `providers` list.
This section needs to be synced with the database every time it changes, using the [`mas-cli config sync`](../usage/cli/config.md#config-sync---prune---dry-run) command.

**An exhaustive list of all the parameters is available in the [configuration file reference](../usage/configuration.md#upstream_oauth2).**

The general configuration usually goes as follows:

 - determine a unique `id` for the provider, which will be used as stable identifier between the configuration file and the database. This `id` must be a ULID, and can be generated using online tools like <https://www.ulidtools.com>
 - create an OAuth 2.0/OIDC client on the provider's side, using the following parameters:
   - `redirect_uri`: `https://<auth-service-domain>/upstream/callback/<id>`
   - `response_type`: `code`
   - `response_mode`: `query`
   - `grant_type`: `authorization_code`
 - fill the `upstream_oauth2` section of the configuration file with the following parameters:
   - `providers`:
     - `id`: the previously generated ULID
     - `client_id`: the client ID of the OAuth 2.0/OIDC client given by the provider
     - `client_secret`: the client secret of the OAuth 2.0/OIDC client given by the provider
     - `issuer`: the issuer URL of the provider
     - `scope`: the scope to request from the provider. `openid` is usually required, and `profile` and `email` are recommended to import a few user attributes.
 - setup user attributes mapping to automatically fill the user profile with data from the provider. See the [user attributes mapping](#user-attributes-mapping) section for more details.

## User attributes mapping

The authentication service supports importing the following user attributes from the provider:

 - The localpart/username (e.g. `@localpart:example.com`)
 - The display name
 - An email address

For each of those attributes, administrators can configure a mapping using the claims provided by the upstream provider.
They can also configure what should be done for each of those attributes. It can either:

 - `ignore`: ignore the attribute, and let the user fill it manually
 - `suggest`: suggest the attribute to the user, but let them opt-out of importing it
 - `force`: automatically import the attribute, but don't fail if it is not provided by the provider
 - `require`: automatically import the attribute, and fail if it is not provided by the provider

A Jinja2 template is used as mapping for each attribute. The template currently has one `user` variable, which is an object with the claims got through the `id_token` given by the provider.
The following default templates are used:

 - `localpart`: `{{ user.preferred_username }}`
 - `displayname`: `{{ user.name }}`
 - `email`: `{{ user.email }}`

## Multiple providers behaviour

Multiple authentication methods can be configured at the same time, in which case the authentication service will let the user choose which one to use.
This is true if both the local password database and an upstream provider are configured, or if multiple upstream providers are configured.
In such cases, the `human_name` parameter of the provider configuration is used to display a human-readable name for the provider, and the `brand_name` parameter is used to show a logo for well-known providers.

If there is only one upstream provider configured and the local password database is disabled ([`passwords.enabled`](../usage/configuration.md#passwords) is set to `false`), the authentication service will automatically trigger an authorization flow with this provider.

## Sample configurations

This section contains sample configurations for popular OIDC providers.

### Authentik

[Authentik](https://goauthentik.io/) is an open-source IdP solution.

1. Create a provider in Authentik, with type OAuth2/OpenID.
2. The parameters are:
  - Client Type: Confidential
  - Redirect URIs: `https://<auth-service-domain>/upstream/callback/<id>`
3. Create an application for the authentication service in Authentik and link it to the provider.
4. Note the slug of your application, Client ID and Client Secret.

Authentication service configuration:

```yaml
upstream_oauth2:
  providers:
    - id: 01HFRQFT5QFMJFGF01P7JAV2ME
      human_name: Authentik
      issuer: "https://<authentik-domain>/application/o/<app-slug>/" # TO BE FILLED
      client_id: "<client-id>" # TO BE FILLED
      client_secret: "<client-secret>" # TO BE FILLED
      scope: "openid profile email"
      claims_imports:
        localpart:
          action: require
          template: "{{ user.preferred_username }}"
        displayname:
          action: suggest
          template: "{{ user.name }}"
        email:
          action: suggest
          template: "{{ user.email }}"
          set_email_verification: always
```


### Facebook

0. You will need a Facebook developer account. You can register for one [here](https://developers.facebook.com/async/registration/).
1. On the [apps](https://developers.facebook.com/apps/) page of the developer console, "Create App", and choose "Allow people to log in with their Facebook account".
2. Once the app is created, add "Facebook Login" and choose "Web". You don't
   need to go through the whole form here.
3. In the left-hand menu, open "Use cases" > "Authentication and account creation" > "Customize" > "Settings"
   * Add `https://<auth-service-domain>/upstream/callback/<id>` as an OAuth Redirect URL.
4. In the left-hand menu, open "App settings/Basic". Here you can copy the "App ID" and "App Secret" for use below.

Authentication service configuration:

```yaml
upstream_oauth2:
  providers:
    - id: "01HFS3WM7KSWCEQVJTN0V9X1W6"
      issuer: "https://www.facebook.com"
      human_name: "Facebook"
      brand_name: "facebook"
      discovery_mode: disabled
      pkce_method: always
      authorization_endpoint: "https://facebook.com/v11.0/dialog/oauth/"
      token_endpoint: "https://graph.facebook.com/v11.0/oauth/access_token"
      jwks_uri: "https://www.facebook.com/.well-known/oauth/openid/jwks/"
      token_endpoint_auth_method: "client_secret_post"
      client_id: "<app-id>" # TO BE FILLED
      client_secret: "<app-secret>" # TO BE FILLED
      scope: "openid"
      claims_imports:
        localpart:
          action: ignore
        displayname:
          action: suggest
          template: "{{ user.name }}"
        email:
          action: suggest
          template: "{{ user.email }}"
          set_email_verification: always
```


### GitLab

1. Create a [new application](https://gitlab.com/profile/applications).
2. Add the `openid` scope. Optionally add the `profile` and `email` scope if you want to import the user's name and email.
3. Add this Callback URL: `https://<auth-service-domain>/upstream/callback/<id>`

Authentication service configuration:

```yaml
upstream_oauth2:
  providers:
    - id: "01HFS67GJ145HCM9ZASYS9DC3J"
      issuer: "https://gitlab.com"
      human_name: "GitLab"
      brand_name: "gitlab"
      token_endpoint_auth_method: "client_secret_post"
      client_id: "<client-id>" # TO BE FILLED
      client_secret: "<client-secret>" # TO BE FILLED
      scope: "openid profile email"
      claims_imports:
        displayname:
          action: suggest
          template: "{{ user.name }}"
        localpart:
          action: ignore
        email:
          action: suggest
          template: "{{ user.email }}"
```


### Google

1. Set up a project in the Google API Console (see [documentation](https://developers.google.com/identity/protocols/oauth2/openid-connect#appsetup))
2. Add an "OAuth Client ID" for a Web Application under ["Credentials"](https://console.developers.google.com/apis/credentials)
3. Add the following "Authorized redirect URI": `https://<auth-service-domain>/upstream/callback/<id>`

Authentication service configuration:

```yaml
upstream_oauth2:
  providers:
    - id: 01HFS6S2SVAR7Y7QYMZJ53ZAGZ
      human_name: Google
      brand_name: "google"
      issuer: "https://accounts.google.com"
      client_id: "<client-id>" # TO BE FILLED
      client_secret: "<client-secret>" # TO BE FILLED
      scope: "openid profile email"
      claims_imports:
        localpart:
          action: ignore
        displayname:
          action: suggest
          template: "{{ user.name }}"
        email:
          action: suggest
          template: "{{ user.email }}"
```


### Keycloak


Follow the [Getting Started Guide](https://www.keycloak.org/guides) to install Keycloak and set up a realm.

1. Click `Clients` in the sidebar and click `Create`
2. Fill in the fields as below:

   | Field | Value |
   |-----------|-----------|
   | Client ID | `matrix-authentication-service` |
   | Client Protocol | `openid-connect` |

3. Click `Save`
4. Fill in the fields as below:

   | Field | Value |
   |-----------|-----------|
   | Client ID | `matrix-authentication-service` |
   | Enabled | `On` |
   | Client Protocol | `openid-connect` |
   | Access Type | `confidential` |
   | Valid Redirect URIs | `https://<auth-service-domain>/upstream/callback/<id>` |

5. Click `Save`
6. On the Credentials tab, update the fields:

   | Field | Value |
   |-------|-------|
   | Client Authenticator | `Client ID and Secret` |

7. Click `Regenerate Secret`
8. Copy Secret

```yaml
upstream_oauth2:
  providers:
    - id: "01H8PKNWKKRPCBW4YGH1RWV279"
      issuer: "https://<keycloak>/realms/<realm>" # TO BE FILLED
      token_endpoint_auth_method: client_secret_basic
      client_id: "matrix-authentication-service"
      client_secret: "<client-secret>" # TO BE FILLED
      scope: "openid profile email"
      claims_imports:
        localpart:
          action: require
          template: "{{ user.preferred_username }}"
        displayname:
          action: suggest
          template: "{{ user.name }}"
        email:
          action: suggest
          template: "{{ user.email }}"
          set_email_verification: always
```


### Microsoft Azure Active Directory

Azure AD can act as an OpenID Connect Provider.
Register a new application under *App registrations* in the Azure AD management console. 
The `RedirectURI` for your application should point to your authentication service instance: 
`https://<auth-service-domain>/upstream/callback/<id>` where `<id>` is the same as in the config file.

Go to *Certificates & secrets* and register a new client secret.
Make note of your Directory (tenant) ID as it will be used in the Azure links.

Authentication service configuration:

```yaml
upstream_oauth2:
  providers:
    - id: "01HFRPWGR6BG9SAGAKDTQHG2R2"
      human_name: Microsoft Azure AD
      issuer: "https://login.microsoftonline.com/<tenant-id>/v2.0" # TO BE FILLED
      client_id: "<client-id>" # TO BE FILLED
      client_secret: "<client-secret>" # TO BE FILLED
      scope: "openid profile email"

      claims_imports:
        localpart:
          action: require
          template: "{{ (user.preferred_username | split('@'))[0] }}"
        displayname:
          action: suggest
          template: "{{ user.name }}"
        email:
          action: suggest
          template: "{{ user.email }}"
          set_email_verification: always
```

