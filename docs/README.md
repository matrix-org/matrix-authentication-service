# About this documentation

This documentation is intended to give an overview of how the `matrix-authentication-service` works, both from an admin perspective and from a developer perspective.

The documentation itself is built using [mdBook](https://rust-lang.github.io/mdBook/).
A hosted version is available at <https://matrix-org.github.io/matrix-authentication-service/>.

## How the documentation is organized

This documentation has four main sections:

- The [installation guide](./setup/README.md) will guide you through the process of setting up the `matrix-authentication-service` on your own infrastructure.
- The topics sections goes into more details about how the service works, like the [policy engine](./topics/policy.md) and how [authorization sessions](./topics/authorization.md) are managed.
- The reference documentation covers [configuration options](./reference/configuration.md), the [GraphQL API](./reference/graphql.md), the [scopes](./reference/scopes.md) supported by the service, and the [command line interface](./reference/cli/).
- The developer documentation is intended for people who want to [contribute to the project](./development/contributing.md). Other links:
  - Technical documentation for individual crates: [`rustdoc`](./rustdoc/mas_handlers/)
  - UI components: [`storybook`](./storybook/)
