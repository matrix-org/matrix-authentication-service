# OAuth2.0 + OpenID Connect Provider for Matrix Homeservers

## matrix-authentication-service is now actively maintained at [element-hq/matrix-authentication-service](https://github.com/element-hq/matrix-authentication-service)

MAS (Matrix Authentication Service) is an OAuth 2.0 and OpenID Provider server for Matrix developed from 2021 through 2024 as part of the Matrix.org Foundation. The Matrix.org Foundation is not able to resource maintenance of matrix-authentication-service and it continues to be developed by Element.

See [The future of Synapse and Dendrite blog post](https://matrix.org/blog/2023/11/06/future-of-synapse-dendrite/) for more information.

---

It has been created to support the migration of Matrix to an OpenID Connect (OIDC) based authentication layer as per [MSC3861](https://github.com/matrix-org/matrix-doc/pull/3861).

See the [Documentation](https://matrix-org.github.io/matrix-authentication-service/index.html) for information on installation and use.

You can learn more about Matrix and OIDC at [areweoidcyet.com](https://areweoidcyet.com/).

![Delegated OIDC architecture with MAS overview](overview.png)

## Features

- Supported homeservers
  - ✅ Synapse
- Authentication methods:
  - ✅ Upstream OIDC
  - 🚧 Local password
  - ‼️ [Application Services login](https://matrix-org.github.io/matrix-authentication-service/as-login.html) (**Encrypted bridges**)
- Migration support
  - ✅ Compatibility layer for legacy Matrix authentication
  - ✅ Advisor on migration readiness
  - ✅ Import users from Synapse
  - ✅ Import password hashes from Synapse
  - ✅ Import of external subject IDs for upstream identity providers from Synapse

## Upstream Identity Providers

MAS is known to work with the following upstream IdPs via OIDC:

- [Keycloak](https://www.keycloak.org/)
- [Dex](https://dexidp.io/)
- [Google](https://developers.google.com/identity/openid-connect/openid-connect)
